package monition

import "sync/atomic"

type CollectionStats struct {
	TotalDistFragMbrLenLte0Num uint64
}

func (t *Monitor) AddTotalDistFragMbrLenLte0Num(delta uint64) uint64 {
	return atomic.AddUint64(&t.collectionStats.TotalDistFragMbrLenLte0Num, delta)
}
