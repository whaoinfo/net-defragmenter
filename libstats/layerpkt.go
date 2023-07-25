package libstats

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type LayerPktErrStats struct {
	TotalNewPacketErrNum                uint64
	TotalSerializeLayersErrNum          uint64
	TotalFullPacketBufAppendBytesErrNum uint64

	TotalIPV4HdrLenInsufficient uint64

	TotalIPv6NetWorkerLayerNilNum      uint64
	TotalIPV6HdrLenInsufficientNum     uint64
	TotalIPV6FragHdrLenInsufficientNum uint64

	TotalUnhandledErrNum uint64
}

func (t *LayerPktErrStats) AddTotalNum(delta uint64, errResultType def.ErrResultType) uint64 {
	var updNum *uint64
	switch errResultType {
	case def.ErrResultTypeNewPacket:
		updNum = &t.TotalNewPacketErrNum
	case def.ErrResultSerializeLayers:
		updNum = &t.TotalSerializeLayersErrNum
	case def.ErrResultFullPacketBufAppendBytes:
		updNum = &t.TotalFullPacketBufAppendBytesErrNum
	case def.ErrResultIPV4HdrLenInsufficient:
		updNum = &t.TotalIPV4HdrLenInsufficient
	case def.ErrResultIPV6NetworkLayerNil:
		updNum = &t.TotalIPv6NetWorkerLayerNilNum
	case def.ErrResultIPV6HdrLenInsufficient:
		updNum = &t.TotalIPV6HdrLenInsufficientNum
	case def.ErrResultIPV6FragHdrLenInsufficient:
		updNum = &t.TotalIPV6FragHdrLenInsufficientNum
	default:
		updNum = &t.TotalUnhandledErrNum
	}

	return atomic.AddUint64(updNum, delta)
}
