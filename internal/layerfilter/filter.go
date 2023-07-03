package layerfilter

import (
	"errors"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"sync/atomic"
)

type Filter struct {
	pickFragTypeSet      map[definition.FragmentType]bool
	totalFilterPassedNum uint64
}

func NewFilter(pickFragTypes []definition.FragmentType) (*Filter, error) {
	pickFragTypeSet := make(map[definition.FragmentType]bool)
	for _, fragTpy := range pickFragTypes {
		if fragTpy <= definition.InvalidFragType || fragTpy >= definition.MaxInvalidFragType {
			continue
		}
		pickFragTypeSet[fragTpy] = true
	}

	if len(pickFragTypeSet) <= 0 {
		return nil, errors.New("no valid pick fragment type")
	}

	return &Filter{pickFragTypeSet: pickFragTypeSet}, nil
}

func (t *Filter) ParseAndFilterPacket(pktBuf []byte) (definition.FragmentType, uint32, error) {
	ethType, ethPayload, parseEthErr := parseLinkLayer(pktBuf)
	if parseEthErr != nil {
		libstats.AddTotalFilterLinkLayerErrNum(1)
		return definition.InvalidFragType, 0, parseEthErr
	}

	ipFragType, identifier, ipProto, ipPayload, ipLayerErr := parseNetWorkerLayer(ethType, ethPayload)
	if ipLayerErr != nil {
		return definition.InvalidFragType, 0, ipLayerErr
	}

	if t.pickFragTypeSet[ipFragType] {
		return ipFragType, identifier, nil
	}

	libstats.AddTotalPickFragTypeNotExistsNum(1)
	// Application layer not currently supported
	if true {
		return definition.InvalidFragType, 0, nil
	}

	appFragType, appParseErr := parseApplicationLayer(ipProto, ipPayload)
	if appParseErr != nil {
		libstats.AddTotalFilterAppLayerErrNum(1)
		return definition.InvalidFragType, 0, appParseErr
	}

	return appFragType, 0, nil
}

func (t *Filter) AddTotalFilterPassedNum() uint64 {
	return atomic.AddUint64(&t.totalFilterPassedNum, 1)
}
