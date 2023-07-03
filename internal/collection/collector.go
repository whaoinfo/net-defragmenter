package collection

import (
	"context"
	"fmt"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/internal/linkqueue"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"time"
)

func newCollector(id, maxListenChanCap uint32, tickerInterval time.Duration,
	compPktQueue *linkqueue.LinkQueue) *Collector {

	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	return &Collector{
		id:             id,
		tickerInterval: tickerInterval,
		cancelCtx:      cancelCtx,
		cancelFunc:     cancelFunc,
		listenChan:     make(chan *fragment.Metadata, maxListenChanCap),
		fragSetMap:     make(map[string]*fragment.Set),
		compPktQueue:   compPktQueue,
	}
}

type Collector struct {
	id             uint32
	tickerInterval time.Duration
	cancelCtx      context.Context
	cancelFunc     context.CancelFunc
	listenChan     chan *fragment.Metadata

	fragSetMap   map[string]*fragment.Set
	compPktQueue *linkqueue.LinkQueue
}

func (t *Collector) start() {
	go t.schedulingCoroutine()
}

func (t *Collector) close() {
	t.cancelFunc()
}

func (t *Collector) stop() {

}

func (t *Collector) schedulingCoroutine() {
	timer := time.NewTicker(t.tickerInterval)

loopExit:
	for {
		select {
		case <-timer.C:
			t.checkFragmentSetExpired()
			break
		case metadata, ok := <-t.listenChan:
			if !ok {
				break loopExit
			}
			if err := t.acceptFragment(metadata); err != nil {
				// todo
			}
			break
		case <-t.cancelCtx.Done():
			break loopExit
		}
	}

	timer.Stop()
	t.stop()
}

func (t *Collector) checkFragmentSetExpired() {
	nowTp := time.Now().Unix()
	var expiredSets []*fragment.Set
	for _, fragSet := range t.fragSetMap {
		if (nowTp - fragSet.GetCreateTimestamp()) > fragSetDurationSec {
			expiredSets = append(expiredSets, fragSet)
		}
	}

	for _, fragSet := range expiredSets {
		delete(t.fragSetMap, fragSet.GetID())
		fragSet.Release()
		libstats.AddTotalReleaseFragSetThExpiredNum(1)
	}
}

func (t *Collector) acceptFragment(fragMetadata *fragment.Metadata) error {
	libstats.AddTotalAcceptFragNum(1)
	hd := handler.GetHandler(fragMetadata.FragType)
	if hd == nil {
		libstats.AddTotalCollectHandleNilErrNum(1)
		return fmt.Errorf("handler with fragment type %v dose not exists", fragMetadata.FragType)
	}

	fragSet, exist := t.fragSetMap[fragMetadata.ID]
	if !exist {
		t.fragSetMap[fragMetadata.ID] = fragment.NewFragmentSet(fragMetadata)
		fragSet = t.fragSetMap[fragMetadata.ID]
		libstats.AddTotalNewFragmentSetNum(1)
	}

	collectErr, collectErrType := hd.Collect(fragMetadata, fragSet)
	if collectErr != nil {
		libstats.AddTotalCollectErrStatsNum(1, collectErrType)
		return collectErr
	}

	libstats.AddTotalAcceptFragSuccessfulNum(1)
	if err := t.checkAndReassembly(fragSet, fragMetadata, hd); err != nil {
		return err
	}

	return nil
}

func (t *Collector) checkAndReassembly(fragSet *fragment.Set, fragMetadata *fragment.Metadata, hd handler.IHandler) error {
	if !fragSet.CheckFinalMetadataExists() || fragSet.GetHighest() != fragSet.GetCurrentLen() {
		return nil
	}

	fragListLen := fragSet.GetFragmentListLen()
	defer func() {
		fragSet.Release()
		libstats.AddTotalReleaseFragSetThReassemblyNum(1)
	}()

	pkt, reassemblyErr, errType := hd.Reassembly(fragSet)
	if reassemblyErr != nil {
		libstats.AddTotalReassemblyErrStatsNum(1, errType)
		return reassemblyErr
	}

	libstats.AddTotalReassemblyFragNum(uint64(fragListLen))
	libstats.AddTotalPushCompletePktNum(1)
	t.compPktQueue.SafetyPutValue(&definition.CompletePacket{
		InIdentifier: fragMetadata.InIdentifier,
		FragGroup:    fragMetadata.FragGroup,
		Pkt:          pkt,
	})

	return nil
}

func (t *Collector) pushFragment(fragMetadata *fragment.Metadata) {
	t.listenChan <- fragMetadata
}
