package builder

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"golang.org/x/time/rate"
)

type CliqueBuilder struct {
	ds        flashbotsextra.IDatabaseService
	relay     IRelay
	eth       IEthereumService
	blockTime time.Duration
	// clique assumes centralized sequencer and therefore has only one proposer configuration.
	proposerPubkey          phase0.BLSPubKey
	proposerFeeRecipient    bellatrix.ExecutionAddress
	proposerGasLimit        uint64
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
	blockTime                     time.Duration
	proposerPubkey                phase0.BLSPubKey
	proposerFeeRecipient          bellatrix.ExecutionAddress
	proposerGasLimit              uint64
	builderSigningDomain          phase0.Domain
	builderBlockResubmitInterval  time.Duration
	eth                           IEthereumService
	limiter                       *rate.Limiter
	submissionOffsetFromEndOfSlot time.Duration
	validator                     *blockvalidation.BlockValidationAPI
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
		proposerPubkey:                args.proposerPubkey,
		proposerFeeRecipient:          args.proposerFeeRecipient,
		proposerGasLimit:              args.proposerGasLimit,
		builderSecretKey:              args.sk,
		builderPublicKey:              pk,
		builderSigningDomain:          args.builderSigningDomain,
		builderResubmitInterval:       args.builderBlockResubmitInterval,
		submissionOffsetFromEndOfSlot: args.submissionOffsetFromEndOfSlot,
		limiter:                       args.limiter,
		slotCtx:                       slotCtx,
		slotCtxCancel:                 slotCtxCancel,
		stop:                          make(chan struct{}, 1),
		blockTime:                     args.blockTime,
	}, nil
}

func (cb *CliqueBuilder) Start() error {
	go func() {
		c := make(chan core.ChainHeadEvent)
		cb.eth.BlockChain().SubscribeChainHeadEvent(c)
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

func (cb *CliqueBuilder) getValidatorData() ValidatorData {
	return ValidatorData{
		Pubkey:       PubkeyHex(cb.proposerPubkey.String()),
		FeeRecipient: cb.proposerFeeRecipient,
		GasLimit:     cb.proposerGasLimit,
	}
}

func (cb *CliqueBuilder) onChainHeadEvent(block *types.Block) error {
	log.Info("Received chain head event", "block", block, "header", block.Header())
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

	slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), 12*time.Second)
	cb.slotBlock = block
	cb.slotCtx = slotCtx
	cb.slotCtxCancel = slotCtxCancel

	attrs := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(block.Header().Time) + hexutil.Uint64(12),
		Random:                common.Hash{},    // unused
		SuggestedFeeRecipient: common.Address{}, // unused
		Slot:                  block.NumberU64() + 1,
		HeadHash:              block.Hash(),
		Withdrawals:           block.Withdrawals(),
		GasLimit:              block.GasLimit(),
	}

	go cb.runBuildingJob(cb.slotCtx, attrs)
	return nil
}

func (cb *CliqueBuilder) runBuildingJob(slotCtx context.Context, attrs *types.BuilderPayloadAttributes) {
	ctx, cancel := context.WithTimeout(slotCtx, cb.blockTime)
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
				queueBestEntry.commitedBundles, queueBestEntry.allBundles, queueBestEntry.usedSbundles, attrs)

			if err != nil {
				log.Error("could not run sealed block hook", "err", err)
			} else {
				queueLastSubmittedHash = queueBestEntry.block.Hash()
			}
		}
		queueMu.Unlock()
	}

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
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, attrs *types.BuilderPayloadAttributes) error {
	log.Info("submitted block", "slot", attrs.Slot, "value", blockValue.String(), "parent", block.ParentHash,
		"hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	if cb.eth.Config().IsShanghai(block.Time()) {
		if err := cb.submitCapellaBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, attrs); err != nil {
			return err
		}
	} else {
		if err := cb.submitBellatrixBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, attrs); err != nil {
			return err
		}
	}

	log.Info("submitted block", "slot", attrs.Slot, "value", blockValue.String(), "parent", block.ParentHash,
		"hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (cb *CliqueBuilder) Stop() error {
	close(cb.stop)
	return nil
}

func (cb *CliqueBuilder) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
	// Not implemented for clique.
	return nil
}

func (cb *CliqueBuilder) submitBellatrixBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	attrs *types.BuilderPayloadAttributes) error {
	executableData := engine.BlockToExecutableData(block, blockValue)
	payload, err := executableDataToExecutionPayload(executableData.ExecutionPayload)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value, overflow := uint256.FromBig(blockValue)
	if overflow {
		log.Error("could not set block value due to value overflow")
		return err
	}

	blockBidMsg := apiv1.BidTrace{
		Slot:                 attrs.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        cb.builderPublicKey,
		ProposerPubkey:       cb.proposerPubkey,
		ProposerFeeRecipient: cb.proposerFeeRecipient,
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	signature, err := ssz.SignMessage(&blockBidMsg, cb.builderSigningDomain, cb.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := bellatrixapi.SubmitBlockRequest{
		Signature:        signature,
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	go cb.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, &blockBidMsg)
	err = cb.relay.SubmitBlock(&blockSubmitReq, cb.getValidatorData())
	if err != nil {
		log.Error("could not submit bellatrix block", "err", err, "#commitedBundles", len(commitedBundles))
		return err
	}

	log.Info("submitted bellatrix block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))

	return nil
}

func (cb *CliqueBuilder) submitCapellaBlock(block *types.Block, blockValue *big.Int, ordersClosedAt, sealedAt time.Time,
	commitedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	attrs *types.BuilderPayloadAttributes) error {
	executableData := engine.BlockToExecutableData(block, blockValue)
	payload, err := executableDataToCapellaExecutionPayload(executableData.ExecutionPayload)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return err
	}

	value, overflow := uint256.FromBig(blockValue)
	if overflow {
		log.Error("could not set block value due to value overflow")
		return err
	}

	blockBidMsg := apiv1.BidTrace{
		Slot:                 attrs.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        cb.builderPublicKey,
		ProposerPubkey:       cb.proposerPubkey,
		ProposerFeeRecipient: cb.proposerFeeRecipient,
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	signature, err := ssz.SignMessage(&blockBidMsg, cb.builderSigningDomain, cb.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return err
	}

	blockSubmitReq := capellaapi.SubmitBlockRequest{
		Signature:        signature,
		Message:          &blockBidMsg,
		ExecutionPayload: payload,
	}

	go cb.ds.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, &blockBidMsg)
	err = cb.relay.SubmitBlockCapella(&blockSubmitReq, cb.getValidatorData())
	if err != nil {
		log.Error("could not submit capella block", "err", err, "#commitedBundles", len(commitedBundles))
		return err
	}

	log.Info("submitted capella block", "slot", blockBidMsg.Slot, "value", blockBidMsg.Value.String(), "parent", blockBidMsg.ParentHash, "hash", block.Hash(), "#commitedBundles", len(commitedBundles))
	return nil
}
