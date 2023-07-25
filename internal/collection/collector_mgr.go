package collection

import (
	"errors"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/common"
	"github.com/whaoinfo/net-defragmenter/internal/linkqueue"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"hash/crc32"
	"sync/atomic"
	"time"
)

const (
	fullPktQueueCheckingSec         = 5
	releaseFullPktAfterSec          = 10
	fragSetDurationSec              = 10
	intervalCheckFragSec            = 5
	intervalRestSharedLayersFragSec = 60 * 5
)

func NewCollectorMgr(opt def.CollectorOption) (*CollectorMgr, error) {
	if opt.MaxCollectorsNum <= 0 {
		return nil, errors.New("the maxMembersNum parameter is less than or equal to 0")
	}
	if opt.MaxChannelCap <= 0 {
		return nil, errors.New("the maxChannelCap parameter is less than or equal to 0")
	}
	if opt.MaxFullPktQueueLen <= 0 {
		return nil, errors.New("the maxFullPktQueueLen parameter is less than or equal to 0")
	}

	fullPktQueue := linkqueue.NewLinkQueue()
	members := make([]*Collector, 0, opt.MaxCollectorsNum)
	for i := 0; i < int(opt.MaxCollectorsNum); i++ {
		members = append(members, newCollector(uint32(i), opt.MaxChannelCap, fullPktQueue))
	}

	mgr := &CollectorMgr{
		status:             def.InitializedStatus,
		members:            members,
		fullPktQueue:       fullPktQueue,
		maxFullPktQueueLen: opt.MaxFullPktQueueLen,
	}
	return mgr, nil
}

type CollectorMgr struct {
	status             int32
	maxFullPktQueueLen uint32
	members            []*Collector
	fullPktQueue       *linkqueue.LinkQueue
}

func (t *CollectorMgr) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, def.InitializedStatus, def.StartedStatus) {
		return
	}

	go t.checkFullPktQueueCapacityPeriodically()
	for _, mbr := range t.members {
		mbr.start()
	}
}

func (t *CollectorMgr) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, def.StartedStatus, def.StoppedStatus) {
		return
	}

	for _, mbr := range t.members {
		mbr.close()
	}
}

func (t *CollectorMgr) Collect(fragGroupID def.FragmentGroupID, detectInfo *def.DetectionInfo, inMarkValue uint64) {
	membersLen := len(t.members)
	if membersLen <= 0 {
		libstats.AddTotalDistributeFragmentFailureNum(1)
		return
	}

	fragElem := common.NewFragmentElement()
	setFragmentElement(fragElem, detectInfo, fragGroupID, inMarkValue)

	hashVal := crc32.ChecksumIEEE([]byte(fragGroupID))
	idx := hashVal % uint32(membersLen)
	mbr := t.members[idx]
	mbr.pushFragmentElement(fragElem)
}

func (t *CollectorMgr) checkFullPktQueueCapacityPeriodically() {
	for {
		if t.status != def.StartedStatus {
			break
		}
		time.Sleep(time.Second * fullPktQueueCheckingSec)
		if t.fullPktQueue.SafetyGetLen() <= int(t.maxFullPktQueueLen) {
			continue
		}
		time.Sleep(time.Second * releaseFullPktAfterSec)
		releaseCount := t.fullPktQueue.SafetyGetLen() - int(t.maxFullPktQueueLen)
		if releaseCount <= 0 {
			continue
		}

		for _, compPkt := range t.fullPktQueue.SafetyPopValues(releaseCount * 2) {
			compPkt.(*def.FullPacket).Pkt = nil
			libstats.AddTotalReleaseFullPktNum(1)
		}
	}
}

func (t *CollectorMgr) PopFullPackets(count int) ([]*def.FullPacket, error) {
	if t.fullPktQueue == nil {
		return nil, errors.New("fullPktQueue is a nil pointer")
	}

	pktValues := t.fullPktQueue.SafetyPopValues(count)
	if len(pktValues) <= 0 {
		return nil, nil
	}

	retPktList := make([]*def.FullPacket, 0, len(pktValues))
	for _, val := range pktValues {
		retPktList = append(retPktList, val.(*def.FullPacket))
	}

	libstats.AddTotalPopFullPktNum(uint64(len(pktValues)))
	return retPktList, nil
}

func setFragmentElement(fragElem *common.FragmentElement, detectInfo *def.DetectionInfo,
	fragGroupID def.FragmentGroupID, inMarkValue uint64) {

	fragElem.Type = detectInfo.FragType
	fragElem.GroupID = fragGroupID
	fragElem.InMarkValue = inMarkValue
	fragElem.FragOffset = detectInfo.FragOffset
	fragElem.MoreFrags = detectInfo.MoreFrags
	fragElem.Identification = detectInfo.Identification
	fragElem.PayloadBuf.Write(detectInfo.IPPayload)

	if fragElem.MoreFrags {
		return
	}

	// layer2
	if len(fragElem.SrcMAC) != len(detectInfo.SrcMAC) {
		fragElem.SrcMAC = make([]byte, len(detectInfo.SrcMAC))
	}
	copy(fragElem.SrcMAC, detectInfo.SrcMAC)

	if len(fragElem.DstMAC) != len(detectInfo.DstMAC) {
		fragElem.DstMAC = make([]byte, len(detectInfo.DstMAC))
	}
	copy(fragElem.DstMAC, detectInfo.DstMAC)

	// layer3
	if len(fragElem.SrcIP) != len(detectInfo.SrcIP) {
		fragElem.SrcIP = make([]byte, len(detectInfo.SrcIP))
	}
	copy(fragElem.SrcIP, detectInfo.SrcIP)

	if len(fragElem.DstIP) != len(detectInfo.DstIP) {
		fragElem.DstIP = make([]byte, len(detectInfo.DstIP))
	}
	copy(fragElem.DstIP, detectInfo.DstIP)
	fragElem.IPProtocol = detectInfo.IPProtocol
}
