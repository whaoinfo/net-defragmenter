package example

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/whaoinfo/net-defragmenter/fragadapter"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"log"
	"runtime"
	"time"
)

func printMemoryStatus(title string) {
	memStats := libstats.CollectMemoryStatus()
	data, _ := json.Marshal(memStats)
	log.Printf("=============%v===========\n", title)
	fmt.Println(string(data))
	log.Println("====================================")
}

func printStats() {
	stats := libstats.GetStatsMgr()
	d, _ := json.Marshal(stats)
	log.Println("=============stats==================")
	fmt.Println(string(d))
	log.Println("====================================")

}

func LaunchDemoWithPcapReply(pcapFilePath string) {
	availableNumCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(availableNumCPU)
	log.Printf("The current number of logical CPUs available for the process is %d\n", availableNumCPU)

	log.Println("Launch demo with replay pcap function")
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start loading the pcap file")
	pcapHandle, openErr := pcap.OpenOffline(pcapFilePath)
	if openErr != nil {
		log.Printf("pcap.OpenOffline failed, %v\n", openErr)
		return
	}
	log.Println("The pcap file has loaded")
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start initializing adapter instance")
	newAdapterErr := fragadapter.InitializeAdapterInstance()
	if newAdapterErr != nil {
		log.Printf("NewDeFragmentAdapter failed, %v\n", newAdapterErr)
		return
	}
	log.Println("Adapter instance initialization completed")
	printMemoryStatus("Memory State")
	fmt.Println()

	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start Adapter instance")
	fragadapter.GetAdapterInstance().Start()
	log.Println("Adapter instance has started")
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Printf("Create two simulation instances and register them")
	inst1 := &simulationInstance{}
	inst1.recordId = fragadapter.GetAdapterInstance().RegisterInstance(inst1)
	inst2 := &simulationInstance{}
	inst2.recordId = fragadapter.GetAdapterInstance().RegisterInstance(inst2)
	log.Println("Simulation instance creation and registration completed")
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start replaying the pcap file")
	tp := time.Now()
	ifIdx := 1
	var totalPktNum int
	var totalPktSize int
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		pktData := packet.Data()
		totalPktNum += 1
		totalPktSize += len(pktData)
		fragadapter.GetAdapterInstance().AsyncProcessPacket(inst1.recordId, tp, ifIdx, pktData)
	}
	log.Printf("PCAP file replay completed, The total number of replay packets is %d, The total size of the replay packets is %d bytes\n",
		totalPktNum, totalPktSize)
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start releasing pcap file")
	pcapHandle.Close()
	log.Println("Pcap file release completed")
	printMemoryStatus("Memory State")
	fmt.Println()

	waiteSec := 30
	log.Printf("Waiting %d seconds\n", waiteSec)
	time.Sleep(time.Second * time.Duration(waiteSec))
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start reclaiming memory")
	runtime.GC()
	log.Println("Memory reclamation completed")
	printMemoryStatus("Memory State")
	fmt.Println()

	log.Println("Start unregistering simulation instances")
	fragadapter.GetAdapterInstance().UnregisterInstance(inst1.recordId)
	fragadapter.GetAdapterInstance().UnregisterInstance(inst2.recordId)
	log.Println("Canceled the registration of these simulation instances")
	printMemoryStatus("Memory State")
	fmt.Println()
	waiteSec = 5
	log.Printf("Waiting %d seconds\n", waiteSec)
	time.Sleep(time.Second * time.Duration(waiteSec))
	fmt.Println()

	log.Println("Start reclaiming memory")
	runtime.GC()
	log.Println("Memory reclamation completed")
	fmt.Println()

	waiteSec = 3
	log.Printf("Waiting %d seconds\n", waiteSec)
	time.Sleep(time.Second * time.Duration(waiteSec))
	fmt.Println()

	log.Println("Start reclaiming memory")
	runtime.GC()
	log.Println("Memory reclamation completed")
	fmt.Println()

	waiteSec = 3
	log.Printf("Waiting %d seconds\n", waiteSec)
	time.Sleep(time.Second * time.Duration(waiteSec))
	fmt.Println()

	printMemoryStatus("Memory State")
	fmt.Println()

	//apInst := fragadapter.GetAdapterInstance()
	//fmt.Println(apInst)
	printStats()
	fmt.Println()
	log.Println("Demo completed")

	if true {
		return
	}

	//time.Sleep(time.Second * 50)
	//fragadapter.GetAdapterInstance().UnregisterInstance(inst1.recordId)
	for {
		time.Sleep(time.Second * 2)
	}
}
