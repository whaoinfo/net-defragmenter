package layerfilter

import (
	"errors"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/monition"
	"sync/atomic"
)

type Filter struct {
	monitor              *monition.Monitor
	pickFragTypeSet      map[definition.FragmentType]bool
	totalFilterPassedNum uint64
}

func NewFilter(pickFragTypes []definition.FragmentType, monitor *monition.Monitor) (*Filter, error) {
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

	return &Filter{monitor: monitor, pickFragTypeSet: pickFragTypeSet}, nil
}

func (t *Filter) ParseAndFilterPacket(pktBuf []byte) (bool, definition.FragmentType, error) {
	ethType, ethPayload, parseEthErr := parseLinkLayer(pktBuf)
	if parseEthErr != nil {
		t.monitor.AddTotalFilterLinkLayerErrNum(1)
		return false, definition.InvalidFragType, parseEthErr
	}

	ipFragType, ipProto, ipPayload, ipLayerErr := parseNetWorkerLayer(ethType, ethPayload)
	if ipLayerErr != nil {
		t.monitor.AddTotalFilterNetLayerErrNum(1)
		return false, definition.InvalidFragType, ipLayerErr
	}

	if t.pickFragTypeSet[ipFragType] {
		return true, ipFragType, nil
	}

	// Application layer not currently supported
	if true {
		return true, definition.InvalidFragType, nil
	}

	appFragType, appParseErr := parseApplicationLayer(ipProto, ipPayload)
	if appParseErr != nil {
		t.monitor.AddTotalFilterAppLayerErrNum(1)
		return false, definition.InvalidFragType, appParseErr
	}

	return true, appFragType, nil
}

func (t *Filter) AddTotalFilterPassedNum() uint64 {
	return atomic.AddUint64(&t.totalFilterPassedNum, 1)
}
