package net_defragmenter

import (
	"errors"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/classification"
	"github.com/whaoinfo/net-defragmenter/internal/collection"
	"github.com/whaoinfo/net-defragmenter/internal/filter"
)

func NewManager(opt *Option) (*Manager, error) {
	// Check the config
	if opt == nil {
		return nil, errors.New("opt is a nil pointer")
	}

	// Create a manager and init it
	mgr := &Manager{
		fragmentTypeFlag: make([]bool, definition.MaxInvalidFragType),
	}
	if err := mgr.initialize(opt); err != nil {
		return nil, err
	}

	// todo
	return mgr, nil
}

type Manager struct {
	fragmentTypeFlag []bool

	classifierMgr *classification.ClassifierMgr
	collectorMgr  *collection.CollectorMgr
}

func (t *Manager) initialize(opt *Option) error {
	for _, fragmentType := range opt.FragmentTypes {
		if fragmentType <= definition.MinInvalidFragType || fragmentType >= definition.MaxInvalidFragType {
			continue
		}
		t.fragmentTypeFlag[fragmentType] = true
	}

	collectorMgr, newCollectorErr := collection.NewCollectorMgr(opt.CollectorOption.MaxCollectorsNum,
		opt.CollectorOption.MaxChannelCap,
		opt.CollectorOption.TickerInterval)
	if newCollectorErr != nil {
		return newCollectorErr
	}
	t.collectorMgr = collectorMgr

	clsMgr, newClsMgrErr := classification.NewClassifierMgr(opt.ClassifierOption.MaxClassifiersNum,
		collectorMgr.DistributeFragment)
	if newClsMgrErr != nil {
		return newClsMgrErr
	}
	t.classifierMgr = clsMgr

	return nil
}

func (t *Manager) Start() {
	t.collectorMgr.Start()
	t.classifierMgr.Start()
}

func (t *Manager) Stop() {
	t.collectorMgr.Stop()
	t.classifierMgr.Stop()
}

func (t *Manager) FilterAndPushPacket(buf []byte) error {
	fragType, filterErr := filter.ExecuteFilterFragment(buf)
	if filterErr != nil {
		return filterErr
	}
	if definition.MinInvalidFragType == fragType || fragType == definition.MaxInvalidFragType {
		return nil
	}

	if err := t.classifierMgr.ClassifyFragmentAsynchronous(fragType, buf); err != nil {
		// todo
		return err
	}

	return nil
}
