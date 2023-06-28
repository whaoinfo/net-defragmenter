package filter

import (
	"github.com/whaoinfo/net-defragmenter/definition"
)

func ExecuteFilterFragment(buf []byte) (definition.FragmentType, error) {
	ethType, ethPayload, parseEthErr := parseLinkLayer(buf)
	if parseEthErr != nil {
		return definition.MinInvalidFragType, parseEthErr
	}

	// check net worker layer
	fragType, passed, ipProto, ipPayload, ipLayerErr := parseAndFilterNetWorkerLayer(ethType, ethPayload)
	if ipLayerErr != nil {
		return definition.MinInvalidFragType, ipLayerErr
	}

	if passed {
		return fragType, nil
	}

	//if l3Protocol == layers.IPv4DontFragment && t.fragmentTypeFlag[definition.IPV4FragmentType] {
	//	return true, definition.IPV4FragmentType, nil
	//}
	//if ipProtocol == layers.IPProtocolIPv6Fragment && t.fragmentTypeFlag[definition.IPV6FragmentType] {
	//	return true, definition.IPV6FragmentType, nil
	//}

	return parseApplicationLayer(ipProto, ipPayload)
}
