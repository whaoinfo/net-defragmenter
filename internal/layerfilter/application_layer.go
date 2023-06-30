package layerfilter

import (
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
)

func parseApplicationLayer(ipProto layers.IPProtocol, payload []byte) (definition.FragmentType, error) {
	// todo
	return definition.InvalidFragType, nil
}
