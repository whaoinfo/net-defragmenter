package monition

func NewMonitor(enable bool) *Monitor {
	return &Monitor{
		enabled:         enable,
		clsStats:        &ClassificationStats{},
		collectionStats: &CollectionStats{},
		filterStats:     &FilterStats{},
	}
}

type Monitor struct {
	enabled         bool
	clsStats        *ClassificationStats
	collectionStats *CollectionStats
	filterStats     *FilterStats
}
