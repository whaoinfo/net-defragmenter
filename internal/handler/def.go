package handler

import (
	"github.com/google/gopacket"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/common"
)

type IHandler interface {
	FastDetect(detectInfo *def.DetectionInfo) (error, def.ErrResultType)
	Collect(fragElem *common.FragmentElement, fragElemSet *common.FragmentElementSet) (error, def.ErrResultType)
	Reassembly(fragElemSet *common.FragmentElementSet, sharedLayers *common.SharedLayers) (gopacket.Packet, error, def.ErrResultType)
}

var (
	defaultSerializeOptions = gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}
)
