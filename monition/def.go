package monition

type ErrorStatsType uint16

const (
	ErrorStatsTypeHandleNil ErrorStatsType = iota
	ErrorStatsTypeNewPacket
	ErrorStatsTypeHdClassify
)
