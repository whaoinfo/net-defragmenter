package classification

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/monition"
	"hash/crc32"
	"sync/atomic"
)

func generateFragmentMetadataID(flowHashVal uint64, fragGroup uint32) string {
	return fmt.Sprintf("%v%v", flowHashVal, fragGroup)
}

type executionContext struct {
	fragType     definition.FragmentType
	pktBuf       []byte
	inIdentifier uint64
}

func newClassifier(id int, distributeFunc fragment.DistributeFragmentFunc, monitor *monition.Monitor) *Classifier {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	return &Classifier{
		id:                     id,
		cancelCtx:              cancelCtx,
		cancelFunc:             cancelFunc,
		ctx:                    make(chan *executionContext),
		monitor:                monitor,
		distributeFragmentFunc: distributeFunc,
	}
}

type Classifier struct {
	id         int
	busyStatus uint32
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
	ctx        chan *executionContext

	monitor                *monition.Monitor
	distributeFragmentFunc fragment.DistributeFragmentFunc
}

func (t *Classifier) start() {
	go t.listen()
}

func (t *Classifier) close() {
	t.cancelFunc()
}

func (t *Classifier) stop() {
	t.distributeFragmentFunc = nil
}

func (t *Classifier) listen() {

loopExit:
	for {
		select {
		case ctx, ok := <-t.ctx:
			if !ok {
				break loopExit
			}

			fragMetadata, genErr := generateFragmentMetadata(ctx.fragType, ctx.pktBuf, ctx.inIdentifier, t.monitor)
			if genErr == nil {
				t.distributeFragmentFunc(fragMetadata)
			}

			ctx.pktBuf = nil
			t.disableBusyStatus()
			break
		case <-t.cancelCtx.Done():
			break loopExit
		}
	}

	t.stop()
}

func (t *Classifier) enableBusyStatus() bool {
	return atomic.CompareAndSwapUint32(&t.busyStatus, 0, 1)
}

func (t *Classifier) disableBusyStatus() {
	atomic.StoreUint32(&t.busyStatus, 0)
	t.monitor.AddTotalRecycleIdleClsMbrNum(1)
}

func generateFragmentMetadata(fragType definition.FragmentType, buf []byte,
	inIdentifier uint64, monitor *monition.Monitor) (*fragment.Metadata, error) {

	hd := handler.GetHandler(fragType)
	if hd == nil {
		monitor.AddTotalGenClsMetaErrorNum(1, monition.ErrorStatsTypeHandleNil)
		return nil, fmt.Errorf("handler with fragment type %v does not exist", fragType)
	}

	pkt := gopacket.NewPacket(buf, layers.LinkTypeEthernet, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		monitor.AddTotalGenClsMetaErrorNum(1, monition.ErrorStatsTypeNewPacket)
		return nil, pkt.ErrorLayer().Error()
	}

	fragMetadata := &fragment.Metadata{FragType: fragType, InIdentifier: inIdentifier}
	if err := hd.Classify(fragMetadata, pkt); err != nil {
		monitor.AddTotalGenClsMetaErrorNum(1, monition.ErrorStatsTypeHdClassify)
		return nil, err
	}

	fragMetadata.ID = generateFragmentMetadataID(fragMetadata.FlowHashValue, fragMetadata.FragGroup)
	fragMetadata.HashValue = crc32.ChecksumIEEE([]byte(fragMetadata.ID))
	fragMetadata.Pkt = pkt

	return fragMetadata, nil
}
