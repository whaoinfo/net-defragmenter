package filter

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
)

func parseAndFilterNetWorkerLayer(ethType layers.EthernetType, payload []byte) (fragType definition.FragmentType,
	retPassed bool, retIpProto layers.IPProtocol, retPayload []byte, retErr error) {

	fragType = definition.MinInvalidFragType
	switch ethType {
	case layers.EthernetTypeIPv4:
		fragType = definition.IPV4FragType
		break
	case layers.EthernetTypeIPv6:
		fragType = definition.IPV6FragType
		break
	default:
		return
	}

	hd := handler.GetHandler(fragType)
	if hd == nil {
		retErr = fmt.Errorf("handler with fragment type %v dose not exists", fragType)
		return
	}

	var iIpProto interface{}
	retPassed, iIpProto, retPayload, retErr = hd.ParseAndFilter(payload)
	retIpProto = iIpProto.(layers.IPProtocol)
	return
}
