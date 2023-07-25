package manager

import (
	"errors"
	"fmt"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/collection"
	"github.com/whaoinfo/net-defragmenter/internal/ctrlapi"
	"github.com/whaoinfo/net-defragmenter/internal/detection"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"sync/atomic"
)

func NewManager(opt *def.Option) (*Manager, error) {
	if opt == nil {
		return nil, errors.New("opt is a nil pointer")
	}

	mgr := &Manager{}
	if err := mgr.initialize(opt); err != nil {
		return nil, err
	}

	return mgr, nil
}

type Manager struct {
	status       int32
	detector     *detection.Detector
	collectorMgr *collection.CollectorMgr
}

func (t *Manager) initialize(opt *def.Option) error {
	if opt.CtrlApiServerOption.Enable {
		if err := ctrlapi.InitCtrlApiServer(opt.CtrlApiServerOption.Port); err != nil {
			return fmt.Errorf("InitCtrlApiServer failed, %v", err)
		}
	}

	libstats.InitStatsMgr(opt.StatsOption)

	detector, newDetectorErr := detection.NewDetector(opt.PickFragmentTypes)
	if newDetectorErr != nil {
		return fmt.Errorf("NewDetector failed, %v", newDetectorErr)
	}

	collectorMgr, newCollectorErr := collection.NewCollectorMgr(opt.CollectorOption)
	if newCollectorErr != nil {
		return fmt.Errorf("NewCollectorMgr failed, %v", newCollectorErr)
	}

	t.detector = detector
	t.collectorMgr = collectorMgr
	t.status = def.InitializedStatus

	return nil
}

func (t *Manager) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, def.InitializedStatus, def.StartedStatus) {
		return
	}

	t.collectorMgr.Start()
}

func (t *Manager) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, def.StartedStatus, def.StoppedStatus) {
		return
	}

	t.collectorMgr.Stop()
}

func (t *Manager) AsyncProcessPacket(pktBuf []byte, inMarkValue uint64, onDetectSuccessful def.OnDetectSuccessfulFunc) error {
	if t.status != def.StartedStatus {
		return fmt.Errorf("manager not started, current status is %v", t.status)
	}

	libstats.AddTotalReceivedPktNum(1)
	var detectInfo def.DetectionInfo
	if err := t.detector.FastDetect(pktBuf, &detectInfo); err != nil {
		return err
	}
	if detectInfo.FragType == def.InvalidFragType {
		return nil
	}

	fragGroupID := detectInfo.GenFragGroupID()
	if onDetectSuccessful != nil {
		onDetectSuccessful(fragGroupID)
	}

	t.collectorMgr.Collect(fragGroupID, &detectInfo, inMarkValue)

	detectInfo.Rest()
	return nil
}

func (t *Manager) PopFullPackets(count int) ([]*def.FullPacket, error) {
	if t.status != def.StartedStatus {
		return nil, fmt.Errorf("manager not started, current status is %v", t.status)
	}

	if t.collectorMgr == nil {
		return nil, errors.New("collectorMgr is a nil pointer")
	}

	return t.collectorMgr.PopFullPackets(count)
}
