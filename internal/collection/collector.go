package collection

import (
	"context"
	"fmt"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/common"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/internal/linkqueue"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"time"
)

func newCollector(id, maxListenChanCap uint32, ptrFullPktQueue *linkqueue.LinkQueue) *Collector {

	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	return &Collector{
		id:              id,
		cancelCtx:       cancelCtx,
		cancelFunc:      cancelFunc,
		listenChan:      make(chan *common.FragmentElement, maxListenChanCap),
		fragElemSetMap:  make(map[def.FragmentGroupID]*common.FragmentElementSet),
		ptrFullPktQueue: ptrFullPktQueue,
		sharedLayers:    common.NewSharedLayers(),
	}
}

type Collector struct {
	id         uint32
	cancelCtx  context.Context
	cancelFunc context.CancelFunc

	listenChan      chan *common.FragmentElement
	fragElemSetMap  map[def.FragmentGroupID]*common.FragmentElementSet
	ptrFullPktQueue *linkqueue.LinkQueue
	sharedLayers    *common.SharedLayers
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
	fragSetCheckTimer := time.NewTicker(time.Second * time.Duration(intervalCheckFragSec))
	sharedLayersRestTimer := time.NewTicker(time.Second * time.Duration(intervalRestSharedLayersFragSec))

loopExit:
	for {
		select {
		case <-fragSetCheckTimer.C:
			t.checkFragmentElementSetExpired()
			break
		case <-sharedLayersRestTimer.C:
			if t.sharedLayers.GetReferencesNum() > 0 {
				t.sharedLayers.Reset()
			}
			break
		case clsData, ok := <-t.listenChan:
			if !ok {
				break loopExit
			}
			if err := t.accept(clsData); err != nil {
				// todo
			}
			break
		case <-t.cancelCtx.Done():
			break loopExit
		}
	}

	fragSetCheckTimer.Stop()
	sharedLayersRestTimer.Stop()

	t.stop()
}

func (t *Collector) checkFragmentElementSetExpired() {
	nowTp := time.Now().Unix()
	var expiredSets []*common.FragmentElementSet
	for _, fragElemSet := range t.fragElemSetMap {
		if (nowTp - fragElemSet.GetCreateTimestamp()) > fragSetDurationSec {
			expiredSets = append(expiredSets, fragElemSet)
		}
	}

	for _, fragElemSet := range expiredSets {
		delete(t.fragElemSetMap, fragElemSet.GetID())
		fragElemSet.Release()
		libstats.AddTotalReleaseFragSetThExpiredNum(1)
	}
}

func (t *Collector) accept(fragElem *common.FragmentElement) error {
	libstats.AddTotalAcceptFragmentElementNum(1)
	hd := handler.GetHandler(fragElem.Type)
	if hd == nil {
		libstats.AddTotalCollectHandleNilErrNum(1)
		return fmt.Errorf("handler with fragment type %v dose not exists", fragElem.Type)
	}

	fragElemSet, exist := t.fragElemSetMap[fragElem.GroupID]
	if !exist {
		t.fragElemSetMap[fragElem.GroupID] = common.NewFragmentElementSet(fragElem.GroupID)
		fragElemSet = t.fragElemSetMap[fragElem.GroupID]
		libstats.AddTotalNewFragmentSetNum(1)
	}

	collectErr, collectErrType := hd.Collect(fragElem, fragElemSet)
	if collectErr != nil {
		libstats.AddTotalCollectErrStatsNum(1, collectErrType)
		return collectErr
	}

	libstats.AddTotalAcceptFragSuccessfulNum(1)
	if err := t.checkAndReassembly(fragElemSet, fragElem, hd); err != nil {
		return err
	}

	return nil
}

func (t *Collector) checkAndReassembly(fragElemSet *common.FragmentElementSet, fragElem *common.FragmentElement, hd handler.IHandler) error {
	if !fragElemSet.CheckFinalElementExists() || fragElemSet.GetHighest() != fragElemSet.GetCurrentLen() {
		return nil
	}

	if _, exist := t.fragElemSetMap[fragElemSet.GetID()]; exist {
		delete(t.fragElemSetMap, fragElemSet.GetID())
	} else {
		libstats.AddTotalDelFragSetNotExistNum(1)
	}

	fragElemListLen := fragElemSet.GetElementListLen()
	defer func() {
		fragElemSet.Release()
		libstats.AddTotalReleaseFragSetThReassemblyNum(1)
	}()

	pkt, reassemblyErr, errType := hd.Reassembly(fragElemSet, t.sharedLayers)
	t.sharedLayers.UpdateReferences()

	if reassemblyErr != nil {
		libstats.AddTotalReassemblyErrStatsNum(1, errType)
		return reassemblyErr
	}

	libstats.AddTotalReassemblyFragNum(uint64(fragElemListLen))
	libstats.AddTotalPushCompletePktNum(1)
	t.ptrFullPktQueue.SafetyPutValue(&def.FullPacket{
		InMarkValue: fragElem.InMarkValue,
		FragGroupID: fragElem.GroupID,
		Pkt:         pkt,
	})

	return nil
}

func (t *Collector) pushFragmentElement(fragElem *common.FragmentElement) {
	t.listenChan <- fragElem
}
