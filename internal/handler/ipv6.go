package handler

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/common"
)

type IPV6Handler struct{}

func (t *IPV6Handler) FastDetect(detectInfo *def.DetectionInfo) (retErr error, retErrType def.ErrResultType) {
	if len(detectInfo.EthPayload) <= def.IPV6HdrLen {
		retErr = fmt.Errorf("the IPV6 packet header length less than %d", def.IPV6HdrLen)
		retErrType = def.ErrResultIPV6HdrLenInsufficient
		return
	}

	buf := detectInfo.EthPayload
	buf = buf[def.IPVersionLen+def.IPV6TrafficClassFlowLabelLen+def.IPV6PayloadLen:]
	if layers.IPProtocol(buf[0]) != layers.IPProtocolIPv6Fragment {
		return
	}

	detectInfo.FragType = def.IPV6FragType

	buf = buf[def.IPV6NextHeaderLen+def.IPV6HopLimitLen:]
	detectInfo.SrcIP = buf[:def.IPV6SrcAddrLen]
	buf = buf[def.IPV6SrcAddrLen:]

	detectInfo.DstIP = buf[:def.IPV6DstAddrLen]
	buf = buf[def.IPV6DstAddrLen:]

	if len(buf) <= def.IPV6FragmentHdrLen {
		retErr = fmt.Errorf("the IPV6 packet fragment header length less than %d", def.IPV6FragmentHdrLen)
		retErrType = def.ErrResultIPV6FragHdrLenInsufficient
		return
	}

	fragHdrBuf := buf[:def.IPV6FragmentHdrLen]
	detectInfo.IPProtocol = layers.IPProtocol(fragHdrBuf[0])
	fragHdrBuf = fragHdrBuf[def.IPV6FragmentNextHeaderLen+def.IPV6FragmentReservedOctetLen:]
	detectInfo.FragOffset = binary.BigEndian.Uint16(fragHdrBuf) >> 3
	detectInfo.MoreFrags = (fragHdrBuf[1] & 0x1) != 0

	fragHdrBuf = fragHdrBuf[def.IPV6FlagsFlagsLen:]
	detectInfo.Identification = binary.BigEndian.Uint32(fragHdrBuf)
	detectInfo.IPPayload = buf[def.IPV6FragmentHdrLen:]

	return
}

func (t *IPV6Handler) Collect(fragElem *common.FragmentElement, fragElemGroup *common.FragmentElementGroup) (error, def.ErrResultType) {
	return collectFragmentElement(fragElem, fragElemGroup)
}

func (t *IPV6Handler) Reassembly(fragElemGroup *common.FragmentElementGroup,
	sharedLayers *common.SharedLayers) (gopacket.Packet, error, def.ErrResultType) {

	finalElem := fragElemGroup.GetFinalElement()
	payloadLen := fragElemGroup.GetAllElementsPayloadLen()

	sharedLayers.EthFrame.SrcMAC = finalElem.SrcMAC
	sharedLayers.EthFrame.DstMAC = finalElem.DstMAC
	sharedLayers.EthFrame.EthernetType = layers.EthernetTypeIPv6

	sharedLayers.IPV6.Length = payloadLen
	sharedLayers.IPV6.NextHeader = finalElem.IPProtocol
	sharedLayers.IPV6.SrcIP = finalElem.SrcIP
	sharedLayers.IPV6.DstIP = finalElem.DstIP

	fullPktBuff := sharedLayers.FullIPV6Buff
	if err := gopacket.SerializeLayers(fullPktBuff, defaultSerializeOptions,
		&sharedLayers.EthFrame, &sharedLayers.IPV6); err != nil {
		return nil, err, def.ErrResultSerializeLayers
	}

	freeLen := len(fullPktBuff.Bytes()) - def.EthIPV6HdrLen
	_, appendErr := fullPktBuff.AppendBytes(int(payloadLen) - freeLen)
	if appendErr != nil {
		return nil, appendErr, def.ErrResultFullPacketBufAppendBytes
	}

	payloadSpace := fullPktBuff.Bytes()[def.EthIPV6HdrLen:]
	fragElemGroup.IterElementList(func(elem *list.Element) bool {
		fragElem := elem.Value.(*common.FragmentElement)
		fragPayloadLen := fragElem.PayloadBuf.Len()
		if fragPayloadLen <= 0 {
			// todo
			return true
		}

		copy(payloadSpace, fragElem.PayloadBuf.Bytes())
		payloadSpace = payloadSpace[fragPayloadLen:]
		return true
	})

	retPkt := gopacket.NewPacket(fullPktBuff.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	if retPkt.ErrorLayer() != nil {
		return nil, retPkt.ErrorLayer().Error(), def.ErrResultTypeNewPacket
	}
	return retPkt, nil, def.NonErrResultType
}
