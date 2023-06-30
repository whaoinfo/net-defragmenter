package collection

import (
	"errors"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/internal/linkqueue"
	"github.com/whaoinfo/net-defragmenter/monition"
	"sync/atomic"
	"time"
)

const (
	compPktQueueCheckingSec = 30
	releaseCompPktAfterSec  = 10
)

func NewCollectorMgr(opt definition.CollectorOption, monitor *monition.Monitor) (*CollectorMgr, error) {
	if opt.MaxCollectorsNum <= 0 {
		return nil, errors.New("the maxMembersNum parameter is less than or equal to 0")
	}
	if opt.MaxChannelCap <= 0 {
		return nil, errors.New("the maxChannelCap parameter is less than or equal to 0")
	}
	if opt.MaxCompPktQueueLen <= 0 {
		return nil, errors.New("the maxCompPktQueueLen parameter is less than or equal to 0")
	}
	if opt.TickerInterval <= 0 {
		return nil, errors.New("the tickerInterval parameter is less than or equal to 0")
	}

	compPktQueue := linkqueue.NewLinkQueue()
	members := make([]*Collector, 0, opt.MaxCollectorsNum)
	for i := 0; i < int(opt.MaxCollectorsNum); i++ {
		members = append(members, newCollector(uint32(i), opt.MaxChannelCap, opt.TickerInterval, compPktQueue, monitor))
	}

	mgr := &CollectorMgr{
		status:             definition.InitializedStatus,
		monitor:            monitor,
		members:            members,
		compPktQueue:       compPktQueue,
		maxCompPktQueueLen: opt.MaxCompPktQueueLen,
	}
	return mgr, nil
}

type CollectorMgr struct {
	status             int32
	monitor            *monition.Monitor
	maxCompPktQueueLen uint32
	members            []*Collector
	compPktQueue       *linkqueue.LinkQueue
}

func (t *CollectorMgr) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.InitializedStatus, definition.StartedStatus) {
		return
	}

	go t.checkCompletePktQueuePeriodically()
	for _, mbr := range t.members {
		mbr.start()
	}
}

func (t *CollectorMgr) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.StartedStatus, definition.StoppedStatus) {
		return
	}

	for _, mbr := range t.members {
		mbr.close()
	}
}

func (t *CollectorMgr) DistributeFragment(fragMetadata *fragment.Metadata) {
	membersLen := len(t.members)
	if membersLen <= 0 {
		t.monitor.AddTotalDistFragMbrLenLte0Num(1)
		return
	}
	idx := fragMetadata.HashValue % uint32(membersLen)
	mbr := t.members[idx]
	mbr.pushFragment(fragMetadata)
}

func (t *CollectorMgr) checkCompletePktQueuePeriodically() {
	for {
		if t.status != definition.StartedStatus {
			break
		}
		time.Sleep(time.Second * compPktQueueCheckingSec)
		if t.compPktQueue.SafetyGetLen() <= int(t.maxCompPktQueueLen) {
			continue
		}
		time.Sleep(time.Second * releaseCompPktAfterSec)
		releaseCount := t.compPktQueue.SafetyGetLen() - int(t.maxCompPktQueueLen)
		if releaseCount <= 0 {
			continue
		}

		for _, compPkt := range t.compPktQueue.SafetyPopValues(releaseCount * 2) {
			//compPkt.(*definition.CompletePacket).Pkt.(gopacket.Packet).NetworkLayer()
			compPkt.(*definition.CompletePacket).Pkt = nil
		}
	}
}

func (t *CollectorMgr) PopCompletePackets(count int) ([]*definition.CompletePacket, error) {
	if t.compPktQueue == nil {
		return nil, errors.New("compPktQueue is a nil pointer")
	}

	pktValues := t.compPktQueue.SafetyPopValues(count)
	if len(pktValues) <= 0 {
		return nil, nil
	}

	retPktList := make([]*definition.CompletePacket, 0, len(pktValues))
	for _, val := range pktValues {
		retPktList = append(retPktList, val.(*definition.CompletePacket))
	}

	return retPktList, nil
}
