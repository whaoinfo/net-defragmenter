package detection

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	def "github.com/whaoinfo/net-defragmenter/definition"
)

func detectEthernetLayer(buf []byte, detectInfo *def.DetectionInfo) error {
	bufLen := len(buf)
	if bufLen <= def.EthHdrLen {
		return fmt.Errorf("the Ethernet frame header length less than %d", def.EthHdrLen)
	}

	dstMac := buf[:def.EthDstLen]
	buf = buf[def.EthDstLen:]
	srcMac := buf[:def.EthSrcLen]
	buf = buf[def.EthSrcLen:]
	ethType := layers.EthernetType(binary.BigEndian.Uint16(buf))
	if ethType != layers.EthernetTypeIPv4 && ethType != layers.EthernetTypeIPv6 {
		return nil
	}

	detectInfo.SrcMAC = srcMac
	detectInfo.DstMAC = dstMac
	detectInfo.EthType = ethType
	detectInfo.EthPayload = buf[def.EthTypeLen:]

	return nil
}
