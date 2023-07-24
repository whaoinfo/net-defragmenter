package common

import (
	"bytes"
	"container/list"
	"github.com/google/gopacket/layers"
	def "github.com/whaoinfo/net-defragmenter/definition"
	"github.com/whaoinfo/net-defragmenter/libstats"
	"sync"
	"time"
)

type FragmentElement struct {
	GroupID     def.FragmentGroupID
	Type        def.FragmentType
	InMarkValue uint64

	SrcMAC, DstMAC []byte
	SrcIP, DstIP   []byte
	IPProtocol     layers.IPProtocol
	FragOffset     uint16
	MoreFrags      bool
	Identification uint32

	PayloadBuf *bytes.Buffer
}

var (
	fragElementObjectPool = &sync.Pool{
		New: func() any {
			libstats.AddTotalAllocateFragmentElementNum(1)
			return &FragmentElement{
				PayloadBuf: &bytes.Buffer{},
			}
		},
	}
)

func NewFragmentElement() *FragmentElement {
	libstats.AddTotalNewFragmentElementNum(1)
	elem := fragElementObjectPool.Get().(*FragmentElement)
	elem.PayloadBuf.Reset()

	return elem
}

func RecycleFragmentElement(elem *FragmentElement) {
	if elem == nil {
		return
	}

	libstats.AddTotalRecycleFragmentElementNum(1)
	elem.PayloadBuf.Reset()
	fragElementObjectPool.Put(elem)
}

func NewFragmentElementSet(fragGroupID def.FragmentGroupID) *FragmentElementSet {
	return &FragmentElementSet{
		groupID:  fragGroupID,
		createTp: time.Now().Unix(),
		elemList: list.New(),
	}
}

type FragmentElementSet struct {
	groupID      def.FragmentGroupID
	createTp     int64
	elemList     *list.List
	highest      uint16
	currentLen   uint16
	ptrFinalElem *FragmentElement
	nextProtocol interface{}
	lastSeen     time.Time
}

func (t *FragmentElementSet) GetID() def.FragmentGroupID {
	return t.groupID
}

func (t *FragmentElementSet) GetHighest() uint16 {
	return t.highest
}

func (t *FragmentElementSet) AddHighest(val uint16) uint16 {
	t.highest += val
	return t.highest
}

func (t *FragmentElementSet) SetHighest(val uint16) {
	t.highest = val
}

func (t *FragmentElementSet) GetCurrentLen() uint16 {
	return t.currentLen
}

func (t *FragmentElementSet) SetNextProtocol(proto interface{}) {
	t.nextProtocol = proto
}

func (t *FragmentElementSet) GetNextProtocol() interface{} {
	return t.nextProtocol
}

func (t *FragmentElementSet) AddCurrentLen(val uint16) uint16 {
	t.currentLen += val
	return t.currentLen
}

func (t *FragmentElementSet) CheckFinalElementExists() bool {
	return t.ptrFinalElem != nil
}

func (t *FragmentElementSet) SetFinalElement(elem *FragmentElement) {
	t.ptrFinalElem = elem
}

func (t *FragmentElementSet) GetFinalElement() *FragmentElement {
	return t.ptrFinalElem
}

func (t *FragmentElementSet) PushElementToBack(elem *FragmentElement) {
	t.elemList.PushBack(elem)
}

func (t *FragmentElementSet) InsertElementToBefore(elem *FragmentElement, mark *list.Element) *list.Element {
	return t.elemList.InsertBefore(elem, mark)
}

func (t *FragmentElementSet) IterElementList(f func(elem *list.Element) bool) {
	for e := t.elemList.Front(); e != nil; e = e.Next() {
		if !f(e) {
			return
		}
	}
}

func (t *FragmentElementSet) GetElementListLen() int {
	return t.elemList.Len()
}

func (t *FragmentElementSet) Release() (clenListLen int) {
	clenListLen = t.cleanUpElementList()
	t.ptrFinalElem = nil
	t.elemList = nil
	return
}

func (t *FragmentElementSet) cleanUpElementList() int {
	var elems []*list.Element
	for e := t.elemList.Front(); e != nil; e = e.Next() {
		elems = append(elems, e)
	}
	for _, elem := range elems {
		t.elemList.Remove(elem)
		if elem.Value == nil {
			continue
		}

		fragElem, ok := elem.Value.(*FragmentElement)
		if !ok {
			continue
		}
		RecycleFragmentElement(fragElem)
	}

	return len(elems)
}

func (t *FragmentElementSet) GetCreateTimestamp() int64 {
	return t.createTp
}

func (t *FragmentElementSet) GetAllElementsPayloadLen() uint16 {
	var totalPayloadLen int
	for e := t.elemList.Front(); e != nil; e = e.Next() {
		elem := e.Value.(*FragmentElement)
		totalPayloadLen += elem.PayloadBuf.Len()
	}
	return uint16(totalPayloadLen)
}
