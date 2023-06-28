package filter

import (
	"encoding/binary"
	"errors"
	"github.com/google/gopacket/layers"
)

const (
	EthDstLen  = 6
	EthSrcLen  = 6
	EthTypeLen = 2
	EthHdrLen  = EthDstLen + EthSrcLen + EthTypeLen
)

func parseLinkLayer(buf []byte) (layers.EthernetType, []byte, error) {
	bufLen := len(buf)
	if bufLen <= EthHdrLen {
		return layers.EthernetTypeLLC, nil, errors.New("unable to parse ethernet frame, insufficient frame length")
	}

	// Offset to ETH TYPE
	buf = buf[EthDstLen+EthSrcLen:]
	ethTypeVal := binary.BigEndian.Uint16(buf)
	payload := buf[EthTypeLen:]
	//return layers.EthernetType(ethType), payload, nil

	ethType := layers.EthernetType(ethTypeVal)
	if ethType == layers.EthernetTypeDot1Q {
		// todo: l2 vlan

	}

	return ethType, payload, nil
}
