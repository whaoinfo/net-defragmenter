package libstats

import (
	"github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type ClassificationStats struct {
	TotalTookIdleMbrNum    uint64
	TotalTakeIdlMbrFailNum uint64
	TotalRecycleIdleMbrNum uint64

	TotalGenNum          uint64
	TotalHandleNilErrNum uint64

	ClsErrStats           LayerPktErrStats
	TotalSuccessfulGenNum uint64
}

func AddTotalGenClsMetadataNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Classification.TotalGenNum, delta)
}

func AddTotalGenClsMetadataSuccessfulNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Classification.TotalSuccessfulGenNum, delta)
}

func AddTotalClsHandleNilErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Classification.TotalHandleNilErrNum, delta)
}

func AddTotalTakeIdleClsMbrNum(succeeded bool, delta uint64) {
	if !mgr.Enabled {
		return
	}
	if succeeded {
		atomic.AddUint64(&mgr.Classification.TotalTookIdleMbrNum, delta)
		return
	}
	atomic.AddUint64(&mgr.Classification.TotalTakeIdlMbrFailNum, delta)
}

func AddTotalRecycleIdleClsMbrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Classification.TotalRecycleIdleMbrNum, delta)
}

func AddTotalClsErrStatsNum(delta uint64, errResultType definition.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Classification.ClsErrStats.AddTotalNum(delta, errResultType)
}
