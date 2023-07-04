package fragadapter

import (
	"github.com/whaoinfo/net-defragmenter/definition"
	"log"
	"sync"
	"time"
)

func NewAdapterRecord(id AdapterRecordIdType, inst IAdapterInstance) *AdapterRecord {
	return &AdapterRecord{
		id:               id,
		inst:             inst,
		fragGroupInfoMap: make(map[uint32]*FragGroupInfo),
	}
}

type AdapterRecord struct {
	id               AdapterRecordIdType
	inst             IAdapterInstance
	fragGroupInfoMap map[uint32]*FragGroupInfo
	mutex            sync.Mutex
}

func (t *AdapterRecord) start() {

}

func (t *AdapterRecord) stop() {

}

func (t *AdapterRecord) close() {

}

func (t *AdapterRecord) release() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	mapLen := len(t.fragGroupInfoMap)
	if mapLen <= 0 {
		return
	}

	keys := make([]uint32, 0, mapLen)
	for key := range t.fragGroupInfoMap {
		keys = append(keys, key)
	}
	for _, key := range keys {
		delete(t.fragGroupInfoMap, key)
	}
}

func (t *AdapterRecord) associatePcapBuf(fragGroup uint32, timestamp time.Time, ifIndex int) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if _, exist := t.fragGroupInfoMap[fragGroup]; exist {
		return
	}

	t.fragGroupInfoMap[fragGroup] = &FragGroupInfo{
		Timestamp: time.Unix(int64(timestamp.Second()), int64(timestamp.Nanosecond())),
		IfIndex:   ifIndex,
	}
}

func (t *AdapterRecord) reassemblyPcapBuf(comPkt *definition.CompletePacket) {
	fragGroup := comPkt.GetFragGroup()
	t.mutex.Lock()
	info, exist := t.fragGroupInfoMap[fragGroup]
	if exist {
		delete(t.fragGroupInfoMap, fragGroup)
	}
	t.mutex.Unlock()

	if info == nil {
		comPkt.Pkt = nil
		log.Printf("[warning][reassemblyPcapBuf] The info with fragGroup %v dose not exists\n", fragGroup)
		return
	}

	pkt := comPkt.GetPacket()
	pktData := pkt.Data()
	comPkt.Pkt = nil

	t.inst.ReassemblyCompletedCallback(info.Timestamp, info.IfIndex, pktData)
}
