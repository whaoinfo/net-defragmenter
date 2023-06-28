package axpcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
)

func TestPcapFileRead(filePath string) {

	for _, file := range []struct {
		filename       string
		num            int
		expectedLayers []gopacket.LayerType
		err            string
	}{
		{filename: filePath,
			num: 24,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeLoopback,
				layers.LayerTypeIPv6,
				layers.LayerTypeTCP,
			},
		},
	} {
		log.Printf("\n\n\n\nProcessing file %s\n\n\n\n", file.filename)

		packets := []gopacket.Packet{}
		if handle, err := pcap.OpenOffline(file.filename); err != nil {
			if file.err != "" {
				if err.Error() != file.err {
					log.Printf("expected message %q; got %q\n", file.err, err.Error())
				}
			} else {
				log.Println(err)
			}
		} else {
			if file.err != "" {
				log.Println("Expected error, got none")
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				log.Println("Packet Dump")
				strD := make([]string, 0, len(packet.Data()))
				for _, d := range packet.Data() {
					strD = append(strD, fmt.Sprintf("%v", d))
				}
				log.Println(strings.Join(strD, ","))
				packets = append(packets, packet)
			}
		}
		if len(packets) != file.num {
			log.Fatal("Incorrect number of packets, want", file.num, "got", len(packets))
		}
		for i, p := range packets {
			log.Println(p.Dump())
			for _, layertype := range file.expectedLayers {
				if p.Layer(layertype) == nil {
					log.Fatal("Packet", i, "has no layer type\n%s", layertype, p.Dump())
				}
			}
		}
	}
}
