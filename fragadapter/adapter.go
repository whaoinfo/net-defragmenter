package fragadapter

import (
	"github.com/whaoinfo/net-defragmenter/definition"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type FragGroupInfo struct {
	Timestamp time.Time
	IfIndex   int
}

const (
	initializeStatus int32 = iota
	initializedStatus
	startedStatus
	stoppedStatus
)

const (
	maxPullCompletePacketsNum = 100
	popComPktInterval         = time.Second * time.Duration(2)
)

type AdapterRecordIdType uint64

type IAdapterInstance interface {
	ReassemblyCompletedCallback(timestamp time.Time, ifIndex int, buf []byte)
}

type NewDeFragmentLibFunc func() (IDeFragmentLib, error)

type IDeFragmentLib interface {
	Start()
	Stop()
	DeliverPacket(pktBuf []byte, inIdentifier uint64) (uint32, error)
	PopCompletePackets(count int) ([]*definition.CompletePacket, error)
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

func (t *DeFragmentAdapter) CheckAndDeliverPacket(id AdapterRecordIdType, timestamp time.Time, ifIndex int, buf []byte) bool {
	//log.Printf("[debug][CheckAndDeliverPacket], id=%v, timestamp=%v, ifIndex=%v, bufLen=%d\n",
	//	id, timestamp, ifIndex, len(buf))

	t.rwMutex.RLock()
	record := t.recordMap[id]
	t.rwMutex.RUnlock()
	if record == nil {
		log.Printf("[warning][CheckAndDeliverPacket] The record %v dose not exists\n", id)
		return false
	}

	fragGroup, err := t.lib.DeliverPacket(buf, uint64(record.id))
	if err != nil {
		log.Printf("[warning][CheckAndDeliverPacket] DeliverPacket error, %v\n", err)
		return false
	}
	if fragGroup <= 0 {
		return false
	}

	record.associatePcapBuf(fragGroup, timestamp, ifIndex)
	return true
}

func (t *DeFragmentAdapter) listenReassemblyCompleted() {
	for {
		time.Sleep(popComPktInterval)

		compPktList, popErr := t.lib.PopCompletePackets(maxPullCompletePacketsNum)
		if popErr != nil {
			log.Printf("[warning][listenReassemblyCompleted] PopCompletePackets error, %v\n", popErr)
			continue
		}
		if len(compPktList) <= 0 {
			continue
		}

		for _, comPkt := range compPktList {
			recordId := AdapterRecordIdType(comPkt.GetInIdentifier())
			record := t.getRecord(recordId)
			if record == nil {
				log.Printf("[warning][listenReassemblyCompleted] The record %v dose not exists\n", comPkt.GetInIdentifier())
				continue
			}

			record.reassemblyPcapBuf(comPkt)
		}
	}
}
