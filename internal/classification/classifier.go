package classification

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/libstats"
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

func newClassifier(id int, distributeFunc fragment.DistributeFragmentFunc) *Classifier {
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	return &Classifier{
		id:                     id,
		cancelCtx:              cancelCtx,
		cancelFunc:             cancelFunc,
		ctx:                    make(chan *executionContext),
		distributeFragmentFunc: distributeFunc,
	}
}

type Classifier struct {
	id         int
	busyStatus uint32
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
	ctx        chan *executionContext

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

			fragMetadata, genErr := generateFragmentMetadata(ctx.fragType, ctx.pktBuf, ctx.inIdentifier)
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
	libstats.AddTotalRecycleIdleClsMbrNum(1)
}

func generateFragmentMetadata(fragType definition.FragmentType, buf []byte,
	inIdentifier uint64) (*fragment.Metadata, error) {

	libstats.AddTotalGenClsMetadataNum(1)
	hd := handler.GetHandler(fragType)
	if hd == nil {
		libstats.AddTotalClsHandleNilErrNum(1)
		return nil, fmt.Errorf("handler with fragment type %v does not exist", fragType)
	}

	pkt := gopacket.NewPacket(buf, layers.LinkTypeEthernet, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		libstats.AddTotalClsErrStatsNum(1, definition.ErrResultTypeNewPacket)
		return nil, pkt.ErrorLayer().Error()
	}

	fragMetadata := &fragment.Metadata{FragType: fragType, InIdentifier: inIdentifier}
	classifyErr, errResultType := hd.Classify(fragMetadata, pkt)
	if classifyErr != nil {
		libstats.AddTotalClsErrStatsNum(1, errResultType)
		return nil, classifyErr
	}

	fragMetadata.ID = generateFragmentMetadataID(fragMetadata.FlowHashValue, fragMetadata.FragGroup)
	fragMetadata.HashValue = crc32.ChecksumIEEE([]byte(fragMetadata.ID))
	fragMetadata.Pkt = pkt
	libstats.AddTotalGenClsMetadataSuccessfulNum(1)

	return fragMetadata, nil
}
