package test

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/whaoinfo/net-defragmenter/example"
	"testing"
)

func TestDebugPacketsInfo(t *testing.T) {
	for _, d := range [][]byte{example.IPv6Frag1, example.IPv6Frag2} {
		pkt := gopacket.NewPacket(d, layers.LinkTypeEthernet, gopacket.Default)
		if pkt.ErrorLayer() != nil {
			t.Error(pkt.ErrorLayer().Error())
			return
		}
	}

	for _, d := range [][]byte{example.IPv4Frag1, example.IPv4Frag2, example.IPv4Frag3} {
		pkt := gopacket.NewPacket(d, layers.LinkTypeEthernet, gopacket.Default)
		if pkt.ErrorLayer() != nil {
			t.Error(pkt.ErrorLayer().Error())
			return
		}
	}

	t.Log("passed")
}
