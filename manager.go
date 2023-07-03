package net_defragmenter

import (
	"errors"
	"fmt"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/classification"
	"github.com/whaoinfo/net-defragmenter/internal/collection"
	"github.com/whaoinfo/net-defragmenter/internal/layerfilter"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"sync/atomic"
)

func NewManager(opt *definition.Option) (*Manager, error) {
	// Check the config
	if opt == nil {
		return nil, errors.New("opt is a nil pointer")
	}

	// Create a manager and init it
	mgr := &Manager{}
	if err := mgr.initialize(opt); err != nil {
		return nil, err
	}

	return mgr, nil
}

type Manager struct {
	status        int32
	filter        *layerfilter.Filter
	classifierMgr *classification.ClassifierMgr
	collectorMgr  *collection.CollectorMgr
}

func (t *Manager) initialize(opt *definition.Option) error {

	filter, newFilterErr := layerfilter.NewFilter(opt.PickFragmentTypes)
	if newFilterErr != nil {
		return fmt.Errorf("NewFilter failed, %v", newFilterErr)
	}

	collectorMgr, newCollectorErr := collection.NewCollectorMgr(opt.CollectorOption)
	if newCollectorErr != nil {
		return fmt.Errorf("NewCollectorMgr failed, %v", newCollectorErr)
	}

	clsMgr, newClsMgrErr := classification.NewClassifierMgr(opt.ClassifierOption, collectorMgr.DistributeFragment)
	if newClsMgrErr != nil {
		return fmt.Errorf("NewClassifierMgr failed, %v", newClsMgrErr)
	}

	t.filter = filter
	t.collectorMgr = collectorMgr
	t.classifierMgr = clsMgr
	t.status = definition.InitializedStatus

	return nil
}

func (t *Manager) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.InitializedStatus, definition.StartedStatus) {
		return
	}

	t.collectorMgr.Start()
	t.classifierMgr.Start()
}

func (t *Manager) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, definition.StartedStatus, definition.StoppedStatus) {
		return
	}

	t.collectorMgr.Stop()
	t.classifierMgr.Stop()
}

func (t *Manager) DeliverPacket(pktBuf []byte, inIdentifier uint64) (uint32, error) {
	if t.status != definition.StartedStatus {
		return 0, fmt.Errorf("manager not started, current status is %v", t.status)
	}

	libstats.AddTotalDeliverPacketPktNum(1)
	fragType, identifier, filterErr := t.filter.ParseAndFilterPacket(pktBuf)
	if filterErr != nil {
		return 0, filterErr
	}

	if fragType <= definition.InvalidFragType || fragType >= definition.MaxInvalidFragType {
		return 0, nil
	}

	if err := t.classifierMgr.ClassifyFragment(fragType, pktBuf, inIdentifier); err != nil {
		return 0, err
	}

	return identifier, nil
}

func (t *Manager) PopCompletePackets(count int) ([]*definition.CompletePacket, error) {
	if t.status != definition.StartedStatus {
		return nil, fmt.Errorf("manager not started, current status is %v", t.status)
	}

	if t.collectorMgr == nil {
		return nil, errors.New("collectorMgr is a nil pointer")
	}

	return t.collectorMgr.PopCompletePackets(count)
}
