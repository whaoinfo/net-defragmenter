package fragadapter

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"log"
	"sync"
	"time"
)

func NewAdapterRecord(id AdapterRecordIdType, inst IAdapterInstance) *AdapterRecord {
	return &AdapterRecord{
		id:              id,
		inst:            inst,
		capturedInfoMap: make(map[def.FragmentGroupID]*CapturedInfo),
	}
}

type AdapterRecord struct {
	id              AdapterRecordIdType
	inst            IAdapterInstance
	capturedInfoMap map[def.FragmentGroupID]*CapturedInfo
	mutex           sync.Mutex
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
	mapLen := len(t.capturedInfoMap)
	if mapLen <= 0 {
		return
	}

	keys := make([]def.FragmentGroupID, 0, mapLen)
	for key := range t.capturedInfoMap {
		keys = append(keys, key)
	}
	for _, key := range keys {
		delete(t.capturedInfoMap, key)
	}
}

func (t *AdapterRecord) associateCapturedInfo(fragGroupID def.FragmentGroupID, timestamp time.Time, ifIndex int) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if _, exist := t.capturedInfoMap[fragGroupID]; exist {
		return
	}

	t.capturedInfoMap[fragGroupID] = &CapturedInfo{
		CreateTp:  time.Now().Unix(),
		Timestamp: time.Unix(int64(timestamp.Second()), int64(timestamp.Nanosecond())),
		IfIndex:   ifIndex,
	}
}

func (t *AdapterRecord) reassemblyCapturedBuf(fullPkt *def.FullPacket) {
	fragGroupID := fullPkt.GetFragGroupID()
	t.mutex.Lock()
	info, exist := t.capturedInfoMap[fragGroupID]
	if exist {
		delete(t.capturedInfoMap, fragGroupID)
	}
	t.mutex.Unlock()

	if info == nil {
		fullPkt.Pkt = nil
		log.Printf("[warning][reassemblyPcapBuf] The info with fragGroup %v dose not exists\n", fragGroupID)
		return
	}

	pkt := fullPkt.GetPacket()
	pktData := pkt.Data()
	fullPkt.Pkt = nil

	t.inst.ReassemblyCompletedCallback(info.Timestamp, info.IfIndex, pktData)
}
