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
	IPV4DifferentiatedSvcFieldLen = 1
	IPV4TotalLengthFieldLen       = 2
	IPV4IdentificationLen         = 2
	IPV4FlagsLen                  = 1
	IPV4FragmentOffsetLen         = 1
	IPV4TimeToLiveLen             = 1
	IPV4ProtocolLen               = 1
	IPV4HeaderChecksumLen         = 2
	IPV4SourceAddressLen          = 4
	IPV4DestinationAddressLen     = 4
	IPV4HdrLen                    = IPVersionLen + IPV4DifferentiatedSvcFieldLen + IPV4TotalLengthFieldLen + IPV4IdentificationLen +
		IPV4FlagsLen + IPV4FragmentOffsetLen + IPV4TimeToLiveLen + IPV4ProtocolLen + IPV4HeaderChecksumLen +
		IPV4SourceAddressLen + IPV4DestinationAddressLen
)

type IPV4Handler struct{}

func (t *IPV4Handler) ParseLayer(buf []byte, reply *definition.ReplyParseLayerParameters) (retErr error, retErrType definition.ErrResultType) {
	bufLen := len(buf)
	if bufLen <= IPV4HdrLen {
		retErr = errors.New("unable to parse IPV4 package, bufLen <= IPV4HdrLen")
		retErrType = definition.ErrResultIPV4HdrLenInsufficient
		return
	}

	buf = buf[IPVersionLen+IPV4DifferentiatedSvcFieldLen+IPV4TotalLengthFieldLen:]
	reply.Identifier = uint32(binary.BigEndian.Uint16(buf))
	buf = buf[IPV4IdentificationLen:]

	ipV4Flags := buf[0]
	fragOffset := buf[1]

	buf = buf[IPV4FlagsLen+IPV4FragmentOffsetLen+IPV4TimeToLiveLen:]
	reply.Proto = layers.IPProtocol(buf[0])

	reply.IsFragType = (fragOffset != 0) || ((ipV4Flags & 0x20) != 0) || ((ipV4Flags & 0x1f) != 0)
	//isFragType = ipV4Flags != 0
	//retPayload = buf[IPV6NextHeaderLen+IPV6HopLimitLen+IPV6SrcAddrLen+IPV6DstAddrLen:]
	return
}

func (t *IPV4Handler) Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) (error, definition.ErrResultType) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return errors.New("the layer3 is a nil pointer"), definition.ErrResultIPV4NetworkLayerNil
	}

	frag, convOk := netLayer.(*layers.IPv4)
	if !convOk {
		return errors.New("the layer3 is not an IPv4 packet"), definition.ErrResultConvIPV4
	}

	fragMetadata.FragGroup = uint32(frag.Id)
	fragMetadata.FlowHashValue = netLayer.NetworkFlow().FastHash()
	return nil, definition.NonErrResultType
}

func (t *IPV4Handler) Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) (error, definition.ErrResultType) {
	frag, convOk := fragMetadata.Pkt.NetworkLayer().(*layers.IPv4)
	if !convOk {
		return errors.New("the layer3 is not an IPv4 packet"), definition.ErrResultConvIPV4
	}

	fragOffset := frag.FragOffset * FragOffsetMulNum
	if fragOffset >= fragSet.GetHighest() {
		fragSet.PushBack(frag)
	} else {
		fragSet.IterElements(func(elem *list.Element) bool {
			elemFrag, _ := elem.Value.(*layers.IPv4)
			if elemFrag.FragOffset == frag.FragOffset {
				// todo
				return false
			}
			if elemFrag.FragOffset > frag.FragOffset {
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
		fragSet.SetNextProtocol(frag.Protocol)
	}

	if frag.Flags == 0 {
		fragSet.SetFinalMetadata(fragMetadata)
	}

	return nil, definition.NonErrResultType
}

func (t *IPV4Handler) Reassembly(fragSet *fragment.Set) (gopacket.Packet, error, definition.ErrResultType) {
	var l3Payload []byte
	fragSet.IterElements(func(elem *list.Element) bool {
		frag, _ := elem.Value.(*layers.IPv4)
		l3Payload = append(l3Payload, frag.Payload...)
		return true
	})

	finalMetadata := fragSet.GetFinalMetadata()
	l2Content := finalMetadata.Pkt.LinkLayer().LayerContents()
	l3Layer := finalMetadata.Pkt.NetworkLayer().(*layers.IPv4)

	newIp := &layers.IPv4{
		Version:    l3Layer.Version,
		IHL:        l3Layer.IHL,
		TOS:        l3Layer.TOS,
		Length:     uint16(len(l3Payload)),
		Id:         0,
		Flags:      0x00,
		FragOffset: 0,
		TTL:        l3Layer.TTL,
		Protocol:   l3Layer.Protocol,
		SrcIP:      l3Layer.SrcIP,
		DstIP:      l3Layer.DstIP,
	}
	//newIp.SrcIP.UnmarshalText([]byte(l3Layer.SrcIP.String()))
	//newIp.DstIP.UnmarshalText([]byte(l3Layer.DstIP.String()))
	defer func() {
		newIp.SrcIP = nil
		newIp.DstIP = nil
	}()

	buf := gopacket.NewSerializeBuffer()
	if err := newIp.SerializeTo(buf, *defaultSerializeOpts); err != nil {
		return nil, err, definition.ErrResultIPv4Serialize
	}

	newPktBuf := make([]byte, len(l2Content)+len(buf.Bytes())+len(l3Payload))
	copy(newPktBuf, l2Content)
	copy(newPktBuf[len(l2Content):], buf.Bytes())
	copy(newPktBuf[len(l2Content)+len(buf.Bytes()):], l3Payload)

	retPkt := gopacket.NewPacket(newPktBuf, layers.LinkTypeEthernet, gopacket.Default)
	if retPkt.ErrorLayer() != nil {
		return nil, retPkt.ErrorLayer().Error(), definition.ErrResultIPV4NewPacket
	}
	return retPkt, nil, definition.NonErrResultType
}
