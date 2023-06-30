package collection

import (
	"context"
	"fmt"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/internal/linkqueue"
	"github.com/whaoinfo/net-defragmenter/monition"
	"time"
)

func newCollector(id, maxListenChanCap uint32, tickerInterval time.Duration,
	compPktQueue *linkqueue.LinkQueue, monitor *monition.Monitor) *Collector {

	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	return &Collector{
		id:             id,
		tickerInterval: tickerInterval,
		cancelCtx:      cancelCtx,
		cancelFunc:     cancelFunc,
		listenChan:     make(chan *fragment.Metadata, maxListenChanCap),
		monitor:        monitor,
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

	monitor      *monition.Monitor
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

}

func (t *Collector) acceptFragment(fragMetadata *fragment.Metadata) error {
	hd := handler.GetHandler(fragMetadata.FragType)
	if hd == nil {
		return fmt.Errorf("handler with fragment type %v dose not exists", fragMetadata.FragType)
	}

	fragSet, exist := t.fragSetMap[fragMetadata.ID]
	if !exist {
		t.fragSetMap[fragMetadata.ID] = fragment.NewFragmentSet(fragMetadata)
		fragSet = t.fragSetMap[fragMetadata.ID]
	}

	if err := hd.Collect(fragMetadata, fragSet); err != nil {
		return err
	}

	if !fragSet.CheckFinalMetadataExists() || fragSet.GetHighest() != fragSet.GetCurrentLen() {
		return nil
	}

	pkt, reassemblyErr := hd.Reassembly(fragSet)
	if reassemblyErr != nil {
		return reassemblyErr
	}

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
