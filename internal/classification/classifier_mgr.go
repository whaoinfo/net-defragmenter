package classification

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"sync/atomic"
)

type ClassifyFuncType = func(fragMetadata *fragment.Metadata, pkt gopacket.Packet) error

var (
	classifyFuncMap = map[definition.FragmentType]ClassifyFuncType{
		//definition.IPV4FragmentType: classifyPacketWithIPV4,
		//definition.IPV6FragmentType: classifyPacketWithIPV6,
	}
)

func getClassifyFunc(fragmentType definition.FragmentType) ClassifyFuncType {
	return classifyFuncMap[fragmentType]
}

func checkClassifyFuncExists(fragmentType definition.FragmentType) bool {
	return classifyFuncMap[fragmentType] != nil
}

func regClassifyFunc(fragmentType definition.FragmentType, f ClassifyFuncType) error {
	classifyFuncMap[fragmentType] = f

	return nil
}

func NewClassifierMgr(opt definition.ClassifierOption, distributeFunc fragment.DistributeFragmentFunc) (*ClassifierMgr, error) {

	if opt.MaxClassifiersNum <= 0 {
		return nil, errors.New("the maxMembersNum parameter is less than or equal to 0")
	}

	members := make([]*Classifier, 0, opt.MaxClassifiersNum)
	for i := 0; i < int(opt.MaxClassifiersNum); i++ {
		members = append(members, newClassifier(i, distributeFunc))
	}

	mgr := &ClassifierMgr{
		status:                 definition.InitializedStatus,
		members:                members,
		distributeFragmentFunc: distributeFunc,
	}

	return mgr, nil
}

type ClassifierMgr struct {
	status                 int32
	totalAllocateNum       uint64
	members                []*Classifier
	distributeFragmentFunc fragment.DistributeFragmentFunc
}

func (t *ClassifierMgr) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.InitializedStatus, definition.StartedStatus) {
		return
	}

	for _, mbr := range t.members {
		mbr.start()
	}
}

func (t *ClassifierMgr) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.StartedStatus, definition.StoppedStatus) {
		return
	}

	for _, mbr := range t.members {
		mbr.stop()
	}
}

func (t *ClassifierMgr) takeIdleMember() *Classifier {
	mbrLen := len(t.members)
	if mbrLen <= 0 {
		return nil
	}

	mbrLen64Num := uint64(mbrLen)
	for i := 0; i < mbrLen; i++ {
		allocateIdx := atomic.AddUint64(&t.totalAllocateNum, 1) % mbrLen64Num
		mbr := t.members[allocateIdx]
		if mbr.enableBusyStatus() {
			return mbr
		}
	}

	return nil
}

func (t *ClassifierMgr) ClassifyFragment(fragType definition.FragmentType, buf []byte, inIdentifier uint64) error {
	mbr := t.takeIdleMember()
	libstats.AddTotalTakeIdleClsMbrNum(mbr != nil, 1)
	if mbr != nil {
		mbr.ctx <- &executionContext{
			fragType:     fragType,
			pktBuf:       buf,
			inIdentifier: inIdentifier,
		}
		return nil
	}

	fragMetadata, genErr := generateFragmentMetadata(fragType, buf, inIdentifier)
	if genErr != nil {
		// todo
		return nil
	}
	t.distributeFragmentFunc(fragMetadata)

	return nil
}
