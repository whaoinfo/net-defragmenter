package layerfilter

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/libstats"
)

func parseNetWorkerLayer(ethType layers.EthernetType, payload []byte) (retFragType definition.FragmentType,
	retIdentifier uint32, retProto layers.IPProtocol, retPayload []byte, retErr error) {

	retFragType = definition.InvalidFragType

	var mappingFragType definition.FragmentType
	switch ethType {
	case layers.EthernetTypeIPv4:
		mappingFragType = definition.IPV4FragType
		break
	case layers.EthernetTypeIPv6:
		mappingFragType = definition.IPV6FragType
		break
	default:
		return
	}

	hd := handler.GetHandler(mappingFragType)
	if hd == nil {
		libstats.AddTotalFilterHandleNilErrNum(1)
		retErr = fmt.Errorf("handler with fragment type %v dose not exists", mappingFragType)
		return
	}

	var reply definition.ReplyParseLayerParameters
	parseErr, parseErrType := hd.ParseLayer(payload, &reply)
	if parseErr != nil {
		retErr = parseErr
		libstats.AddTotalFilterErrStatsNum(1, parseErrType)
		return
	}

	retProto = reply.Proto.(layers.IPProtocol)
	if !reply.IsFragType {
		return
	}

	//retIdentifier = reply.Identifier
	retFragType = mappingFragType
	return
}
