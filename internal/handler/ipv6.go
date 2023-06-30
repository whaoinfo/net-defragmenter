package handler

import (
	"container/list"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
)

var (
	defaultSerializeOpts = &gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
)

type IPV6Handler struct{}

func (t *IPV6Handler) ParseLayer(buf []byte) (isFragType bool,
	retProto interface{}, retPayload []byte, retErr error) {

	bufLen := len(buf)
	if bufLen <= IPV6HdrLen {
		retErr = errors.New("unable to parse IPV6 package, bufLen <= IPV6HdrLen")
		return
	}

	// Offset to next header
	buf = buf[IPVersionLen+IPV6TrafficClassFlowLabelLen+IPV6PayloadLen:]
	retProto = layers.IPProtocol(buf[0])
	isFragType = retProto == layers.IPProtocolIPv6Fragment
	retPayload = buf[IPV6NextHeaderLen+IPV6HopLimitLen+IPV6SrcAddrLen+IPV6DstAddrLen:]
	return
}

func (t *IPV6Handler) Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) error {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return errors.New("layer3 is a nil pointer")
	}

	if len(pkt.Layers()) < 3 {
		return errors.New("layers less than 3")
	}

	frag, convOk := pkt.Layers()[2].(*layers.IPv6Fragment)
	if !convOk {
		return errors.New("layer3 is not an IPv4 Fragment")
	}

	fragMetadata.FragGroup = frag.Identification
	fragMetadata.FlowHashValue = netLayer.NetworkFlow().FastHash()
	return nil
}

func (t *IPV6Handler) Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) error {
	frag, convOk := fragMetadata.Pkt.Layers()[2].(*layers.IPv6Fragment)
	if !convOk {
		return errors.New("the layer3 is not an IPv6 Fragment")
	}

	fragOffset := frag.FragmentOffset * 8
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

	return nil
}

func (t *IPV6Handler) Reassembly(fragSet *fragment.Set) (gopacket.Packet, error) {
	var l3Payload []byte
	fragSet.IterElements(func(elem *list.Element) bool {
		frag, _ := elem.Value.(*layers.IPv6Fragment)
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
		return nil, err
	}

	newPktBuf := make([]byte, len(l2Content)+len(buf.Bytes())+len(l3Payload))
	copy(newPktBuf, l2Content)
	copy(newPktBuf[len(l2Content):], buf.Bytes())
	copy(newPktBuf[len(l2Content)+len(buf.Bytes()):], l3Payload)

	retPkt := gopacket.NewPacket(newPktBuf, layers.LinkTypeEthernet, gopacket.Default)
	if retPkt.ErrorLayer() != nil {
		return nil, retPkt.ErrorLayer().Error()
	}
	return retPkt, nil
}
