package handler

import (
	"github.com/google/gopacket"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/common"
)

type IHandler interface {
	FastDetect(detectInfo *def.DetectionInfo) (error, def.ErrResultType)
	Collect(fragElem *common.FragmentElement, fragElemGroup *common.FragmentElementGroup) (error, def.ErrResultType)
	Reassembly(fragElemGroup *common.FragmentElementGroup, sharedLayers *common.SharedLayers) (gopacket.Packet, error, def.ErrResultType)
}

var (
	defaultSerializeOptions = gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}
)
