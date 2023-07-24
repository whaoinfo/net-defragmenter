package libstats

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type FilterStats struct {
	TotalDeliverPacketPktNum   uint64
	TotalFilterLinkLayerErrNum uint64

	TotalHandleNilErrNum uint64

	FilterErrStats LayerPktErrStats

	//TotalFilterNetLayerErrNum     uint64
	TotalPickFragTypeNotExistsNum uint64
	TotalFilterAppLayerErrNum     uint64
	TotalFilterPassedNum          uint64
}

func AddTotalDeliverPacketPktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalDeliverPacketPktNum, delta)
}

func AddTotalFilterLinkLayerErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalFilterLinkLayerErrNum, delta)
}

func AddTotalFilterHandleNilErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalHandleNilErrNum, delta)
}

func AddTotalPickFragTypeNotExistsNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalPickFragTypeNotExistsNum, delta)
}

func AddTotalFilterAppLayerErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalFilterAppLayerErrNum, delta)
}

func AddTotalFilterPassedNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Filter.TotalFilterPassedNum, delta)
}

func AddTotalFilterErrStatsNum(delta uint64, errResultType def.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Filter.FilterErrStats.AddTotalNum(delta, errResultType)
}
