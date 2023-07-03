package handler

import (
	"github.com/google/gopacket"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
)

type IHandler interface {
	ParseLayer(buf []byte, reply *definition.ReplyParseLayerParameters) (retErr error, retErrType definition.ErrResultType)
	Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) (error, definition.ErrResultType)
	Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) (error, definition.ErrResultType)
	Reassembly(fragSet *fragment.Set) (gopacket.Packet, error, definition.ErrResultType)
}
