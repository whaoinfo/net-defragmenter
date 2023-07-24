package libstats

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"sync/atomic"
)

type LayerPktErrStats struct {
	TotalNewPacketErrNum uint64

	TotalIPV4NetWorkerLayerNilNum uint64
	TotalConvIPV4ErrNum           uint64
	TotalSerializeIPV4ErrNum      uint64
	TotalIPV4NewPacketErrNum      uint64
	TotalIPV4HdrLenInsufficient   uint64

	TotalIPv6NetWorkerLayerNilNum      uint64
	TotalNoIPV6FragLayerNum            uint64
	TotalConvIPV6FragErrNum            uint64
	TotalSerializeIPV6ErrNum           uint64
	TotalIPV6NewPacketErrNum           uint64
	TotalIPV6HdrLenInsufficientNum     uint64
	TotalIPV6FragHdrLenInsufficientNum uint64

	TotalUnhandledErrNum uint64
}

func (t *LayerPktErrStats) AddTotalNum(delta uint64, errResultType def.ErrResultType) uint64 {
	var updNum *uint64
	switch errResultType {
	case def.ErrResultTypeNewPacket:
		updNum = &t.TotalNewPacketErrNum
	case def.ErrResultIPV4NetworkLayerNil:
		updNum = &t.TotalIPV4NetWorkerLayerNilNum
	case def.ErrResultConvIPV4:
		updNum = &t.TotalConvIPV4ErrNum
	case def.ErrResultIPv4Serialize:
		updNum = &t.TotalSerializeIPV4ErrNum
	case def.ErrResultIPV4NewPacket:
		updNum = &t.TotalIPV4NewPacketErrNum
	case def.ErrResultIPV4HdrLenInsufficient:
		updNum = &t.TotalIPV4HdrLenInsufficient
	case def.ErrResultIPV6NetworkLayerNil:
		updNum = &t.TotalIPv6NetWorkerLayerNilNum
	case def.ErrResultNoIPV6FragLayer:
		updNum = &t.TotalNoIPV6FragLayerNum
	case def.ErrResultConvIPv6Frag:
		updNum = &t.TotalConvIPV6FragErrNum
	case def.ErrResultIPv6Serialize:
		updNum = &t.TotalSerializeIPV6ErrNum
	case def.ErrResultTypeIPV6NewPacket:
		updNum = &t.TotalIPV6NewPacketErrNum
	case def.ErrResultIPV6HdrLenInsufficient:
		updNum = &t.TotalIPV6HdrLenInsufficientNum
	case def.ErrResultIPV6FragHdrLenInsufficient:
		updNum = &t.TotalIPV6FragHdrLenInsufficientNum
	default:
		updNum = &t.TotalUnhandledErrNum
	}

	return atomic.AddUint64(updNum, delta)
}
