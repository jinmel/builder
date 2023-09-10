package builder

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"golang.org/x/time/rate"
)

type CliqueBuilder struct {
	ds                      flashbotsextra.IDatabaseService
	relay                   IRelay
	eth                     IEthereumService
	proposerPubkey          phase0.BLSPubKey
	builderSecretKey        *bls.SecretKey
	builderPublicKey        phase0.BLSPubKey
	builderSigningDomain    phase0.Domain
	builderResubmitInterval time.Duration
	limiter                 *rate.Limiter

	submissionOffsetFromEndOfSlot time.Duration
	slotMu                        sync.Mutex
	slotBlock                     *types.Block
	slotCtx                       context.Context
	slotCtxCancel                 context.CancelFunc

	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	stop chan struct{}
}

type CliqueBuilderArgs struct {
	sk                            *bls.SecretKey
	ds                            flashbotsextra.IDatabaseService
	relay                         IRelay
	proposerPubkey                phase0.BLSPubKey
	builderSigningDomain          phase0.Domain
	builderBlockResubmitInterval  time.Duration
	eth                           IEthereumService
	limiter                       *rate.Limiter
	submissionOffsetFromEndOfSlot time.Duration
}

func NewCliqueBuilder(args CliqueBuilderArgs) (*CliqueBuilder, error) {
	blsPk, err := bls.PublicKeyFromSecretKey(args.sk)
	if err != nil {
		return nil, err
	}

	pk, err := utils.BlsPublicKeyToPublicKey(blsPk)
	if err != nil {
		return nil, err
	}

	if args.limiter == nil {
		args.limiter = rate.NewLimiter(rate.Every(RateLimitIntervalDefault), RateLimitBurstDefault)
	}

	if args.builderBlockResubmitInterval == 0 {
		args.builderBlockResubmitInterval = BlockResubmitIntervalDefault
	}

	if args.submissionOffsetFromEndOfSlot == 0 {
		args.submissionOffsetFromEndOfSlot = SubmissionOffsetFromEndOfSlotSecondsDefault
	}

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())

	return &CliqueBuilder{
		ds:                            args.ds,
		relay:                         args.relay,
		eth:                           args.eth,
		proposerPubkey:                args.proposerPubkey, // assumes single proposer pubkey
		builderSecretKey:              args.sk,
		builderPublicKey:              pk,
		builderSigningDomain:          args.builderSigningDomain,
		builderResubmitInterval:       args.builderBlockResubmitInterval,
		submissionOffsetFromEndOfSlot: args.submissionOffsetFromEndOfSlot,
		limiter:                       args.limiter,
		slotCtx:                       slotCtx,
		slotCtxCancel:                 slotCtxCancel,
		stop:                          make(chan struct{}, 1),
	}, nil
}

func (cb *CliqueBuilder) Start() error {
	go func() {
		c := make(chan core.ChainHeadEvent)
		cb.eth.BlockChain().SubscribeChainHeadEvent(c)
		currentSlot := uint64(0)
		for {
			select {
			case <-cb.stop:
				return
			case head := <-c:
				cb.onChainHeadEvent(head.Block)
			}
		}
	}()

	return cb.relay.Start()
}

func (cb *CliqueBuilder) onChainHeadEvent(block *types.Block) error {
	if block == nil {
		return nil
	}

	if !cb.eth.Synced() {
		return errors.New("not synced")
	}

	cb.slotMu.Lock()
	defer cb.slotMu.Unlock()
	if cb.slotCtxCancel != nil {
		cb.slotCtxCancel()
	}

	slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), 6*time.Second)
	cb.slotBlock = block
	cb.slotCtx = slotCtx
	cb.slotCtxCancel = slotCtxCancel

	attrs := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(block.Header().Time),
		Random:                common.Hash{},    // unused
		SuggestedFeeRecipient: common.Address{}, // unused
		Slot:                  block.NumberU64() + 1,
		HeadHash:              block.Hash(),
		Withdrawals:           block.Withdrawals(),
		GasLimit:              block.GasLimit(),
	}

	go cb.runBuildingJob(cb.slotCtx, cb.proposerPubkey, attrs)
	return nil
}

func (cb *CliqueBuilder) runBuildingJob(slotCtx context.Context, proposerPubkey phase0.BLSPubKey, attrs *types.BuilderPayloadAttributes) {
	ctx, cancel := context.WithTimeout(slotCtx, 12*time.Second)
	defer cancel()

	// Submission queue for the given payload attributes
	// multiple jobs can run for different attributes fot the given slot
	// 1. When new block is ready we check if its profit is higher than profit of last best block
	//    if it is we set queueBest* to values of the new block and notify queueSignal channel.
	// 2. Submission goroutine waits for queueSignal and submits queueBest* if its more valuable than
	//    queueLastSubmittedProfit keeping queueLastSubmittedProfit to be the profit of the last submission.
	//    Submission goroutine is globally rate limited to have fixed rate of submissions for all jobs.
	var (
		queueSignal = make(chan struct{}, 1)

		queueMu                sync.Mutex
		queueLastSubmittedHash common.Hash
		queueBestEntry         blockQueueEntry
	)

	log.Debug("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash, "payloadTimestamp", uint64(attrs.Timestamp))

	submitBestBlock := func() {
		queueMu.Lock()
		if queueBestEntry.block.Hash() != queueLastSubmittedHash {
			err := cb.onSealedBlock(queueBestEntry.block, queueBestEntry.blockValue, queueBestEntry.ordersCloseTime, queueBestEntry.sealedAt,
				queueBestEntry.commitedBundles, queueBestEntry.allBundles, queueBestEntry.usedSbundles, proposerPubkey, attrs)

			if err != nil {
				log.Error("could not run sealed block hook", "err", err)
			} else {
				queueLastSubmittedHash = queueBestEntry.block.Hash()
			}
		}
		queueMu.Unlock()
	}

	// Avoid submitting early into a given slot. For example if slots have 12 second interval, submissions should
	// not begin until 8 seconds into the slot.
	slotTime := time.Unix(int64(attrs.Timestamp), 0).UTC()
	slotSubmitStartTime := slotTime.Add(-cb.submissionOffsetFromEndOfSlot)

	// Empties queue, submits the best block for current job with rate limit (global for all jobs)
	go runResubmitLoop(ctx, cb.limiter, queueSignal, submitBestBlock, slotSubmitStartTime)

	// Populates queue with submissions that increase block profit
	blockHook := func(block *types.Block, blockValue *big.Int, ordersCloseTime time.Time,
		committedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	) {
		if ctx.Err() != nil {
			return
		}

		sealedAt := time.Now()

		queueMu.Lock()
		defer queueMu.Unlock()
		if block.Hash() != queueLastSubmittedHash {
			queueBestEntry = blockQueueEntry{
				block:           block,
				blockValue:      new(big.Int).Set(blockValue),
				ordersCloseTime: ordersCloseTime,
				sealedAt:        sealedAt,
				commitedBundles: committedBundles,
				allBundles:      allBundles,
				usedSbundles:    usedSbundles,
			}

			select {
			case queueSignal <- struct{}{}:
			default:
			}
		}
	}

	// resubmits block builder requests every builderBlockResubmitInterval
	runRetryLoop(ctx, cb.builderResubmitInterval, func() {
		log.Debug("retrying BuildBlock",
			"slot", attrs.Slot,
			"parent", attrs.HeadHash,
			"resubmit-interval", cb.builderResubmitInterval.String())
		err := cb.eth.BuildBlock(attrs, blockHook)
		if err != nil {
			log.Warn("Failed to build block", "err", err)
		}
	})
}

func (cb *CliqueBuilder) onSealedBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	proposerPubkey phase0.BLSPubKey, attrs *types.BuilderPayloadAttributes) error {
	log.Info("submitted block", "slot", attrs.Slot, "value", blockValue.String(), "parent", block.ParentHash,
		"hash", block.Hash(), "#commitedBundles", len(commitedBundles))
	return nil
}

func (cb *CliqueBuilder) Stop() error {
	close(cb.stop)
	return nil
}

func (cb *CliqueBuilder) OnPayloadAttribute() error {
	// Not implemented for clique.
	return nil
}
