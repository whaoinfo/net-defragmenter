package libstats

//func NewStatsMgr(enable bool) *StatsMgr {
//	return &StatsMgr{
//		enabled:         enable,
//		clsStats:        &ClassificationStats{},
//		collectionStats: &CollectionStats{},
//		filterStats:     &FilterStats{},
//	}
//}

var (
	mgr = &StatsMgr{}
)

type StatsMgr struct {
	Enabled bool
	Filter  FilterStats
	//Classification ClassificationStats
	Collection CollectionStats
}

func EnableStats(enableStats bool) {
	mgr.Enabled = enableStats
}

func GetStats() StatsMgr {
	return *mgr
}
