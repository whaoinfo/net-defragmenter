package libstats

import (
	"github.com/whaoinfo/net-defragmenter/definition"
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

func (t *LayerPktErrStats) AddTotalNum(delta uint64, errResultType definition.ErrResultType) uint64 {
	var updNum *uint64
	switch errResultType {
	case definition.ErrResultTypeNewPacket:
		updNum = &t.TotalNewPacketErrNum

	case definition.ErrResultIPV4NetworkLayerNil:
		updNum = &t.TotalIPV4NetWorkerLayerNilNum
	case definition.ErrResultConvIPV4:
		updNum = &t.TotalConvIPV4ErrNum
	case definition.ErrResultIPv4Serialize:
		updNum = &t.TotalSerializeIPV4ErrNum
	case definition.ErrResultIPV4NewPacket:
		updNum = &t.TotalIPV4NewPacketErrNum
	case definition.ErrResultIPV4HdrLenInsufficient:
		updNum = &t.TotalIPV4HdrLenInsufficient

	case definition.ErrResultIPV6NetworkLayerNil:
		updNum = &t.TotalIPv6NetWorkerLayerNilNum
	case definition.ErrResultNoIPV6FragLayer:
		updNum = &t.TotalNoIPV6FragLayerNum
	case definition.ErrResultConvIPv6Frag:
		updNum = &t.TotalConvIPV6FragErrNum
	case definition.ErrResultIPv6Serialize:
		updNum = &t.TotalSerializeIPV6ErrNum
	case definition.ErrResultTypeIPV6NewPacket:
		updNum = &t.TotalIPV6NewPacketErrNum
	case definition.ErrResultIPV6HdrLenInsufficient:
		updNum = &t.TotalIPV6HdrLenInsufficientNum
	case definition.ErrResultIPV6FragHdrLenInsufficient:
		updNum = &t.TotalIPV6FragHdrLenInsufficientNum
	default:
		updNum = &t.TotalUnhandledErrNum
	}

	return atomic.AddUint64(updNum, delta)
}
