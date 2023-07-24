package fragadapter

import (
	def "github.com/whaoinfo/net-defragmenter/definition"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type CapturedInfo struct {
	Timestamp time.Time
	IfIndex   int
	CreateTp  int64
}

const (
	initializeStatus int32 = iota
	initializedStatus
	startedStatus
	stoppedStatus
)

const (
	maxPullFullPacketsNum = 5000
	popPullPktInterval    = time.Second * time.Duration(2)
)

type AdapterRecordIdType uint64

type IAdapterInstance interface {
	ReassemblyCompletedCallback(timestamp time.Time, ifIndex int, buf []byte)
}

type NewDeFragmentLibFunc func() (IDeFragmentLib, error)

type IDeFragmentLib interface {
	Start()
	Stop()
	AsyncProcessPacket(pktBuf []byte, inMarkValue uint64, onDetectSuccessful def.OnDetectSuccessfulFunc) error
	PopFullPackets(count int) ([]*def.FullPacket, error)
}

var (
	adapterInstance *DeFragmentAdapter
)

func InitializeAdapterInstance(newLibFunc NewDeFragmentLibFunc) error {
	if adapterInstance != nil {
		return nil
	}

	inst, newInstErr := NewDeFragmentAdapter(newLibFunc)
	if newInstErr != nil {
		return newInstErr
	}

	adapterInstance = inst
	return nil
}

func GetAdapterInstance() *DeFragmentAdapter {
	return adapterInstance
}

func NewDeFragmentAdapter(newLibFunc NewDeFragmentLibFunc) (*DeFragmentAdapter, error) {
	lib, newLibErr := newLibFunc()
	if newLibErr != nil {
		return nil, newLibErr
	}

	adapter := &DeFragmentAdapter{
		status:    initializedStatus,
		lib:       lib,
		recordMap: make(map[AdapterRecordIdType]*AdapterRecord),
	}

	return adapter, nil
}

type DeFragmentAdapter struct {
	status      int32
	lib         IDeFragmentLib
	incRecordId AdapterRecordIdType
	recordMap   map[AdapterRecordIdType]*AdapterRecord
	rwMutex     sync.RWMutex
}

func (t *DeFragmentAdapter) Start() {
	if !atomic.CompareAndSwapInt32(&t.status, initializedStatus, startedStatus) {
		return
	}

	t.lib.Start()
	go t.listenReassemblyCompleted()
}

func (t *DeFragmentAdapter) Stop() {
	if !atomic.CompareAndSwapInt32(&t.status, startedStatus, stoppedStatus) {
		return
	}

	t.clearUpRecords()
	t.lib.Stop()
}

func (t *DeFragmentAdapter) getRecord(id AdapterRecordIdType) *AdapterRecord {
	t.rwMutex.RLock()
	record := t.recordMap[id]
	t.rwMutex.RUnlock()
	return record
}

func (t *DeFragmentAdapter) clearUpRecords() {
	delMap := make(map[AdapterRecordIdType]*AdapterRecord)
	t.rwMutex.Lock()
	for id, record := range t.recordMap {
		delMap[id] = record
	}
	t.rwMutex.Unlock()

	for _, record := range delMap {
		record.release()
	}
}

func (t *DeFragmentAdapter) RegisterInstance(inst IAdapterInstance) (retId AdapterRecordIdType) {
	t.rwMutex.Lock()
	defer t.rwMutex.Unlock()

	t.incRecordId += 1
	retId = t.incRecordId
	t.recordMap[retId] = NewAdapterRecord(retId, inst)

	return
}

func (t *DeFragmentAdapter) UnregisterInstance(id AdapterRecordIdType) {
	t.rwMutex.Lock()
	delInstRecord, exist := t.recordMap[id]
	if exist {
		delete(t.recordMap, id)
	}
	t.rwMutex.Unlock()

	delInstRecord.release()
}

func (t *DeFragmentAdapter) AsyncProcessPacket(id AdapterRecordIdType, timestamp time.Time, ifIndex int, buf []byte) bool {
	//log.Printf("[debug][CheckAndDeliverPacket], id=%v, timestamp=%v, ifIndex=%v, bufLen=%d\n",
	//	id, timestamp, ifIndex, len(buf))
	t.rwMutex.RLock()
	record := t.recordMap[id]
	t.rwMutex.RUnlock()
	if record == nil {
		log.Printf("[warning][CheckAndDeliverPacket] The record %v dose not exists\n", id)
		return false
	}

	//fragGroupID, err := t.lib.AsyncProcessPacket(buf, uint64(record.id), func(clsData *definition.FragmentInfo) {
	//	record.associateCapturedInfo(fragGroupID, timestamp, ifIndex)
	//})

	var fragGroupID def.FragmentGroupID
	var processErr error
	processErr = t.lib.AsyncProcessPacket(buf, uint64(record.id), func(fragGroupID def.FragmentGroupID) {
		record.associateCapturedInfo(fragGroupID, timestamp, ifIndex)
	})
	if processErr != nil {
		log.Printf("[warning][CheckAndDeliverPacket] FilterAndDeliverPacket error, %v\n", processErr)
		return false
	}

	if fragGroupID == "" {
		return false
	}

	return true
}

func (t *DeFragmentAdapter) listenReassemblyCompleted() {
	for {
		time.Sleep(popPullPktInterval)

		fullPktList, popErr := t.lib.PopFullPackets(maxPullFullPacketsNum)
		if popErr != nil {
			log.Printf("[warning][listenReassemblyCompleted] PopFullPackets error, %v\n", popErr)
			continue
		}
		if len(fullPktList) <= 0 {
			continue
		}

		for _, pkt := range fullPktList {
			recordId := AdapterRecordIdType(pkt.GetInMarkValue())
			record := t.getRecord(recordId)
			if record == nil {
				log.Printf("[warning][listenReassemblyCompleted] The record %v dose not exists\n", pkt.GetInMarkValue())
				continue
			}

			record.reassemblyCapturedBuf(pkt)
		}
	}
}
