package libstats

import (
	"github.com/whaoinfo/net-defragmenter/definition"
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
	TotalAcceptFragNum                uint64
	TotalHandleNilErrNum              uint64
	CollectErrStats                   LayerPktErrStats
	TotalAcceptFragSuccessfulNum      uint64

	ReassemblyErrStats LayerPktErrStats

	TotalNewFragSetNum                 uint64
	TotalDelFragSetNotExistNum         uint64
	TotalReleaseFragSetThReassemblyNum uint64
	TotalReleaseFragSetThExpiredNum    uint64

	TotalReassemblyFragNum     uint64
	TotalPushCompletePktNum    uint64
	TotalPopCompletePktNum     uint64
	TotalReleaseCompletePktNum uint64
}

func AddTotalNewFragmentSetNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalNewFragSetNum, delta)
}

func AddTotalDelFragSetNotExistNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalDelFragSetNotExistNum, delta)
}

func AddTotalReleaseFragSetThReassemblyNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseFragSetThReassemblyNum, delta)
}

func AddTotalReleaseFragSetThExpiredNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseFragSetThExpiredNum, delta)
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

func AddTotalAcceptFragNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalAcceptFragNum, delta)
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

func AddTotalCollectErrStatsNum(delta uint64, errResultType definition.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Collection.CollectErrStats.AddTotalNum(delta, errResultType)
}

func AddTotalReassemblyErrStatsNum(delta uint64, errResultType definition.ErrResultType) {
	if !mgr.Enabled {
		return
	}
	mgr.Collection.ReassemblyErrStats.AddTotalNum(delta, errResultType)
}

func AddTotalPushCompletePktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalPushCompletePktNum, delta)
}

func AddTotalReleaseCompletePktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalReleaseCompletePktNum, delta)
}

func AddTotalPopCompletePktNum(delta uint64) {
	if !mgr.Enabled {
		return
	}
	atomic.AddUint64(&mgr.Collection.TotalPopCompletePktNum, delta)
}
