package handler

import (
	"container/list"
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
)

const (
	IPVersionLen                 = 1
	IPV6TrafficClassFlowLabelLen = 3
	IPV6PayloadLen               = 2
	IPV6NextHeaderLen            = 1
	IPV6HopLimitLen              = 1
	IPV6SrcAddrLen               = 16
	IPV6DstAddrLen               = 16
	IPV6HdrLen                   = IPVersionLen + IPV6TrafficClassFlowLabelLen + IPV6PayloadLen + IPV6NextHeaderLen +
		IPV6HopLimitLen + IPV6SrcAddrLen + IPV6DstAddrLen
	IPV6FragmentHdr                 = 8
	IPV6FragHdrIdentificationOffset = 4

	IPV6FragLayerIdx = 2

	FragOffsetMulNum = 8
)

var (
	defaultSerializeOpts = &gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
)

type IPV6Handler struct{}

func (t *IPV6Handler) ParseLayer(buf []byte, reply *definition.ReplyParseLayerParameters) (retErr error, retErrType definition.ErrResultType) {
	bufLen := len(buf)
	if bufLen <= IPV6HdrLen {
		retErr = errors.New("unable to parse IPV6 package, bufLen <= IPV6HdrLen")
		retErrType = definition.ErrResultIPV6HdrLenInsufficient
		return
	}

	// Offset to next header
	buf = buf[IPVersionLen+IPV6TrafficClassFlowLabelLen+IPV6PayloadLen:]
	reply.Proto = layers.IPProtocol(buf[0])
	reply.IsFragType = reply.Proto == layers.IPProtocolIPv6Fragment
	payload := buf[IPV6NextHeaderLen+IPV6HopLimitLen+IPV6SrcAddrLen+IPV6DstAddrLen:]
	if !reply.IsFragType {
		return
	}

	if len(payload) <= IPV6FragmentHdr {
		retErr = errors.New("unable to parse IPV6 fragment header, len(retPayload) <= IPV6FragmentHdr")
		retErrType = definition.ErrResultIPV6FragHdrLenInsufficient
		return
	}
	fragmentHeader := payload[:IPV6FragmentHdr]
	identifierBytes := fragmentHeader[IPV6FragHdrIdentificationOffset:]
	reply.Identifier = binary.BigEndian.Uint32(identifierBytes)

	return
}

func (t *IPV6Handler) Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) (error, definition.ErrResultType) {
	pktLayers := pkt.Layers()
	if len(pktLayers) <= IPV6FragLayerIdx {
		return errors.New("layers less than 3"), definition.ErrResultNoIPV6FragLayer
	}
	frag, convOk := pkt.Layers()[IPV6FragLayerIdx].(*layers.IPv6Fragment)
	if !convOk {
		return errors.New("layer3 is not an IPv4 Fragment"), definition.ErrResultConvIPv6Frag
	}

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return errors.New("layer3 is a nil pointer"), definition.ErrResultIPV6NetworkLayerNil
	}

	fragMetadata.FragGroup = frag.Identification
	fragMetadata.FlowHashValue = netLayer.NetworkFlow().FastHash()
	return nil, definition.NonErrResultType
}

func (t *IPV6Handler) Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) (error, definition.ErrResultType) {
	pktLayers := fragMetadata.Pkt.Layers()
	if len(pktLayers) <= IPV6FragLayerIdx {
		return errors.New("the layer3 is not an IPv6 Fragment"), definition.ErrResultNoIPV6FragLayer
	}

	frag, convOk := fragMetadata.Pkt.Layers()[IPV6FragLayerIdx].(*layers.IPv6Fragment)
	if !convOk {
		return errors.New("the layer3 is not an IPv6 Fragment"), definition.ErrResultConvIPv6Frag
	}

	fragOffset := frag.FragmentOffset * FragOffsetMulNum
	if fragOffset >= fragSet.GetHighest() {
		fragSet.PushBack(frag)
	} else {
		fragSet.IterElements(func(elem *list.Element) bool {
			elemFrag, _ := elem.Value.(*layers.IPv6Fragment)
			if elemFrag.FragmentOffset == frag.FragmentOffset {
				// todo
				return false
			}
			if elemFrag.FragmentOffset > frag.FragmentOffset {
				fragSet.InsertBefore(frag, elem)
				return false
			}
			return true
		})
	}

	fragLength := uint16(len(frag.Payload))
	if fragSet.GetHighest() < fragOffset+fragLength {
		fragSet.SetHighest(fragOffset + fragLength)
	}

	fragSet.AddCurrentLen(fragLength)
	if !fragSet.CheckFinalMetadataExists() {
		fragSet.SetNextProtocol(frag.NextHeader)
	}

	if !frag.MoreFragments {
		fragSet.SetFinalMetadata(fragMetadata)
	}

	return nil, definition.NonErrResultType
}

func (t *IPV6Handler) Reassembly(fragSet *fragment.Set) (gopacket.Packet, error, definition.ErrResultType) {
	var l3Payload []byte
	fragSet.IterElements(func(elem *list.Element) bool {
		frag, ok := elem.Value.(*layers.IPv6Fragment)
		if !ok {
			// todo
			return true
		}
		l3Payload = append(l3Payload, frag.Payload...)
		return true
	})

	finalMetadata := fragSet.GetFinalMetadata()
	finalFragment := finalMetadata.Pkt.Layers()[2].(*layers.IPv6Fragment)
	l2Content := finalMetadata.Pkt.LinkLayer().LayerContents()
	l3Layer := finalMetadata.Pkt.Layers()[1].(*layers.IPv6)

	newIp := &layers.IPv6{
		Version:      l3Layer.Version,
		TrafficClass: l3Layer.TrafficClass,
		FlowLabel:    l3Layer.FlowLabel,
		Length:       uint16(len(l3Payload)),
		NextHeader:   finalFragment.NextHeader,
		HopLimit:     l3Layer.HopLimit,
		SrcIP:        l3Layer.SrcIP,
		DstIP:        l3Layer.DstIP,
	}
	//newIp.SrcIP.UnmarshalText([]byte(l3Layer.SrcIP.String()))
	//newIp.DstIP.UnmarshalText([]byte(l3Layer.DstIP.String()))
	defer func() {
		newIp.SrcIP = nil
		newIp.DstIP = nil
	}()

	buf := gopacket.NewSerializeBuffer()
	if err := newIp.SerializeTo(buf, *defaultSerializeOpts); err != nil {
		return nil, err, definition.ErrResultIPv6Serialize
	}

	newPktBuf := make([]byte, len(l2Content)+len(buf.Bytes())+len(l3Payload))
	copy(newPktBuf, l2Content)
	copy(newPktBuf[len(l2Content):], buf.Bytes())
	copy(newPktBuf[len(l2Content)+len(buf.Bytes()):], l3Payload)

	retPkt := gopacket.NewPacket(newPktBuf, layers.LinkTypeEthernet, gopacket.Default)
	if retPkt.ErrorLayer() != nil {
		return nil, retPkt.ErrorLayer().Error(), definition.ErrResultTypeIPV6NewPacket
	}
	return retPkt, nil, definition.NonErrResultType
}
