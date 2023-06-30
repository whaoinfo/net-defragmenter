package monition

import "sync/atomic"

type GenClsMetadataStats struct {
	TotalHandleIsNilNum  uint64
	TotalNewPacketErrNum uint64
	TotalClassifyErrNum  uint64
}

type ClassificationStats struct {
	TotalTookIdleMbrNum    uint64
	TotalTakeIdlMbrFailNum uint64
	TotalRecycleIdleMbrNum uint64
	GenClsMetadataStats    GenClsMetadataStats
}

func (t *Monitor) AddTotalTakeIdleClsMbrNum(succeeded bool, delta uint64) uint64 {
	if succeeded {
		return atomic.AddUint64(&t.clsStats.TotalTookIdleMbrNum, delta)
	}
	return atomic.AddUint64(&t.clsStats.TotalTakeIdlMbrFailNum, delta)
}

func (t *Monitor) AddTotalRecycleIdleClsMbrNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.clsStats.TotalRecycleIdleMbrNum, delta)
}

func (t *Monitor) AddTotalGenClsMetaErrorNum(delta uint64, errType ErrorStatsType) uint64 {
	var updNum *uint64
	switch errType {
	case ErrorStatsTypeHandleNil:
		updNum = &t.clsStats.GenClsMetadataStats.TotalHandleIsNilNum
	case ErrorStatsTypeNewPacket:
		updNum = &t.clsStats.GenClsMetadataStats.TotalNewPacketErrNum
	case ErrorStatsTypeHdClassify:
		updNum = &t.clsStats.GenClsMetadataStats.TotalClassifyErrNum
	default:
		return 0
	}

	return atomic.AddUint64(updNum, delta)
}
