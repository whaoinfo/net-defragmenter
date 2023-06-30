package layerfilter

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
)

func parseNetWorkerLayer(ethType layers.EthernetType, payload []byte) (definition.FragmentType, layers.IPProtocol,
	[]byte, error) {

	fragType := definition.GetFragmentTypeByLayerEnum(ethType)
	hd := handler.GetHandler(fragType)
	if hd == nil {
		return definition.InvalidFragType, 0, nil, fmt.Errorf("handler with fragment type %v dose not exists", fragType)
	}

	isFragType, iIpProto, retPayload, parseErr := hd.ParseLayer(payload)
	if parseErr != nil {
		return definition.InvalidFragType, 0, nil, parseErr
	}

	retIpProto := iIpProto.(layers.IPProtocol)
	if !isFragType {
		fragType = definition.InvalidFragType
	}

	return fragType, retIpProto, retPayload, nil
}
