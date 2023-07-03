package example

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/fragadapter"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"github.com/whaoinfo/net-defragmenter/manager"
	"log"
	"time"
)

func LaunchDemoWithPcapReply(pcapFilePath string) {
	pcapHandle, openErr := pcap.OpenOffline(pcapFilePath)
	if openErr != nil {
		log.Printf("pcap.OpenOffline failed, %v\n", openErr)
		return
	}

	newAdapterErr := fragadapter.InitializeAdapterInstance(func() (fragadapter.IDeFragmentLib, error) {
		opt := definition.NewOption(func(opt *definition.Option) {
			opt.PickFragmentTypes = []definition.FragmentType{definition.IPV4FragType, definition.IPV6FragType}
			opt.ClassifierOption.MaxClassifiersNum = 10

			opt.CollectorOption.MaxCollectorsNum = 10
			opt.CollectorOption.MaxChannelCap = 200
			opt.CollectorOption.TickerInterval = 200
			opt.CollectorOption.MaxCompPktQueueLen = 200
		})

		libstats.EnableStats(true)

		lib, newLibErr := manager.NewManager(opt)
		if newLibErr != nil {
			return nil, newLibErr
		}
		return lib, nil
	})
	if newAdapterErr != nil {
		log.Printf("NewDeFragmentAdapter failed, %v\n", newAdapterErr)
		return
	}

	go func() {
		if err := startMonitor(); err != nil {
			log.Printf("startMonitor failed, %v\n", err)
		}
	}()

	fragadapter.GetAdapterInstance().Start()

	inst1 := &adapterInstance{}
	inst1.recordId = fragadapter.GetAdapterInstance().RegisterInstance(inst1)
	inst2 := &adapterInstance{}
	inst2.recordId = fragadapter.GetAdapterInstance().RegisterInstance(inst2)

	tp := time.Now()
	ifIdx := 1

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		fragadapter.GetAdapterInstance().CheckAndDeliverPacket(inst1.recordId, tp, ifIdx, packet.Data())
	}

	//time.Sleep(time.Second * 50)
	//fragadapter.GetAdapterInstance().UnregisterInstance(inst1.recordId)
	for {
		time.Sleep(time.Second * 2)
	}
}
