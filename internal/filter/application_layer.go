package filter

import (
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
)

func parseApplicationLayer(ipProtocol layers.IPProtocol, payload []byte) (definition.FragmentType, error) {
	// todo
	return definition.MinInvalidFragType, nil
}
