package detection

import (
	"fmt"
	"github.com/google/gopacket/layers"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/handler"
	"github.com/whaoinfo/net-defragmenter/libstats"
)

func (t *Detector) detectNetworkLayer(detectInfo *def.DetectionInfo) error {
	var mappingFragType def.FragmentType
	switch detectInfo.EthType {
	case layers.EthernetTypeIPv4:
		mappingFragType = def.IPV4FragType
		break
	case layers.EthernetTypeIPv6:
		mappingFragType = def.IPV6FragType
		break
	default:
		return nil
	}

	if !t.pickFragTypeSet[mappingFragType] {
		return nil
	}

	hd := handler.GetHandler(mappingFragType)
	if hd == nil {
		libstats.AddTotalDetectHandleNilErrNum(1)
		return fmt.Errorf("handler with fragment type %v dose not exists", mappingFragType)
	}

	detectErr, detectErrType := hd.FastDetect(detectInfo)
	if detectErr != nil {
		libstats.AddTotalDetectErrStatsNum(1, detectErrType)
		return detectErr
	}

	return nil
}
