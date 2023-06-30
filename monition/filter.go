package monition

import "sync/atomic"

type FilterStats struct {
	TotalDeliverPacketPktNum   uint64
	TotalFilterLinkLayerErrNum uint64
	TotalFilterNetLayerErrNum  uint64
	TotalFilterAppLayerErrNum  uint64
	TotalFilterPassedNum       uint64
}

func (t *Monitor) AddTotalDeliverPacketPktNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.filterStats.TotalDeliverPacketPktNum, delta)
}

func (t *Monitor) AddTotalFilterLinkLayerErrNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.filterStats.TotalFilterLinkLayerErrNum, delta)
}

func (t *Monitor) AddTotalFilterNetLayerErrNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.filterStats.TotalFilterNetLayerErrNum, delta)
}

func (t *Monitor) AddTotalFilterAppLayerErrNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.filterStats.TotalFilterAppLayerErrNum, delta)
}

func (t *Monitor) AddTotalFilterPassedNum(delta uint64) uint64 {
	return atomic.AddUint64(&t.filterStats.TotalFilterPassedNum, delta)
}
