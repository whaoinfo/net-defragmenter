package collection

import (
	"errors"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
	"sync/atomic"
	"time"
)

func NewCollectorMgr(maxMembersNum, maxChannelCap int, tickerInterval time.Duration) (*CollectorMgr, error) {
	if maxMembersNum <= 0 {
		return nil, errors.New("the maxMembersNum parameter is less than or equal to 0")
	}

	members := make([]*Collector, 0, maxMembersNum)
	for i := 0; i < maxMembersNum; i++ {
		members = append(members, newCollector(i, maxChannelCap, tickerInterval))
	}

	mgr := &CollectorMgr{
		members: members,
	}
	return mgr, nil
}

type CollectorMgr struct {
	status  int32
	members []*Collector
}

func (t *CollectorMgr) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.InitStatus, definition.StartedStatus) {
		return
	}

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
		// todo
		return
	}
	idx := fragMetadata.HashValue % uint32(membersLen)
	mbr := t.members[idx]
	mbr.pushFragment(fragMetadata)
}
