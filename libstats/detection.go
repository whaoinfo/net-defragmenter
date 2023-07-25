package libstats

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type DetectionStats struct {
	TotalReceivedPktNum           uint64
	TotalLinkLayerErrNum          uint64
	TotalHandleNilErrNum          uint64
	ErrStats                      LayerPktErrStats
	TotalPickFragTypeNotExistsNum uint64
	TotalFilterAppLayerErrNum     uint64
	TotalDetectPassedNum          uint64
}

func AddTotalReceivedPktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalReceivedPktNum, delta)
}

func AddTotalDetectLinkLayerErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalLinkLayerErrNum, delta)
}

func AddTotalDetectHandleNilErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalHandleNilErrNum, delta)
}

func AddTotalPickFragTypeNotExistsNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalPickFragTypeNotExistsNum, delta)
}

func AddTotalDetectAppLayerErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalFilterAppLayerErrNum, delta)
}

func AddTotalDetectPassedNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Detection.TotalDetectPassedNum, delta)
}

func AddTotalDetectErrStatsNum(delta uint64, errResultType def.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Detection.ErrStats.AddTotalNum(delta, errResultType)
}
