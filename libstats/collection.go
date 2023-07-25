package libstats

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type CollectErrStats struct {
	TotalConvIPV4ErrNum uint64

	TotalNoIPV6FragLayerNum       uint64
	TotalConvIPV6FragErrNum       uint64
	TotalIPv6NetWorkerLayerNilNum uint64
}

type CollectionStats struct {
	TotalDistributeFragmentFailureNum uint64

	TotalNewFragmentElementNum      uint64
	TotalAllocateFragmentElementNum uint64
	TotalRecycleFragmentElementNum  uint64

	TotalAcceptFragmentElementNum uint64
	TotalHandleNilErrNum          uint64
	CollectErrStats               LayerPktErrStats
	TotalAcceptFragSuccessfulNum  uint64

	ReassemblyErrStats LayerPktErrStats

	TotalNewFragGroupNum                 uint64
	TotalDelFragGroupNotExistNum         uint64
	TotalReleaseFragGroupThReassemblyNum uint64
	TotalReleaseFragGroupThExpiredNum    uint64

	TotalReassemblyFragNum uint64
	TotalPushFullPktNum    uint64
	TotalPopFullPktNum     uint64
	TotalReleaseFullPktNum uint64
}

func AddTotalNewFragmentGroupNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalNewFragGroupNum, delta)
}

func AddTotalDelFragGroupNotExistNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalDelFragGroupNotExistNum, delta)
}

func AddTotalReleaseFragGroupThReassemblyNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseFragGroupThReassemblyNum, delta)
}

func AddTotalReleaseFragGroupThExpiredNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseFragGroupThExpiredNum, delta)
}

func AddTotalReassemblyFragNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReassemblyFragNum, delta)
}

func AddTotalDistributeFragmentFailureNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalDistributeFragmentFailureNum, delta)
}

func AddTotalNewFragmentElementNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalNewFragmentElementNum, delta)
}

func AddTotalAllocateFragmentElementNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalAllocateFragmentElementNum, delta)
}

func AddTotalRecycleFragmentElementNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalRecycleFragmentElementNum, delta)
}

func AddTotalAcceptFragmentElementNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalAcceptFragmentElementNum, delta)
}

func AddTotalAcceptFragSuccessfulNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalAcceptFragSuccessfulNum, delta)
}

func AddTotalCollectHandleNilErrNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalHandleNilErrNum, delta)
}

func AddTotalCollectErrStatsNum(delta uint64, errResultType def.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Collection.CollectErrStats.AddTotalNum(delta, errResultType)
}

func AddTotalReassemblyErrStatsNum(delta uint64, errResultType def.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Collection.ReassemblyErrStats.AddTotalNum(delta, errResultType)
}

func AddTotalPushFullPktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalPushFullPktNum, delta)
}

func AddTotalReleaseFullPktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseFullPktNum, delta)
}

func AddTotalPopFullPktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalPopFullPktNum, delta)
}
