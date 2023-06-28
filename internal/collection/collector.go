package collection

import (
	"context"
	"fmt"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"time"
)

func newCollector(id, maxListenChanCap int, tickerInterval time.Duration) *Collector {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())

	return &Collector{
		id:             id,
		tickerInterval: tickerInterval,
		cancelCtx:      cancelCtx,
		cancelFunc:     cancelFunc,
		listenChan:     make(chan *fragment.Metadata, maxListenChanCap),
		fragSetMap:     make(map[string]*fragment.Set),
	}
}

type Collector struct {
	id             int
	tickerInterval time.Duration
	cancelCtx      context.Context
	cancelFunc     context.CancelFunc
	listenChan     chan *fragment.Metadata

	fragSetMap map[string]*fragment.Set
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

	hd.Reassembly(fragSet)

	return nil
}

func (t *Collector) pushFragment(fragMetadata *fragment.Metadata) {
	t.listenChan <- fragMetadata
}
