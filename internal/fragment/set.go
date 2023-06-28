package fragment

import (
	"container/list"
	"time"
)

type DistributeFragmentFunc func(*Metadata)

func NewFragmentSet(metadata *Metadata) *Set {
	return &Set{
		id:       metadata.ID,
		createTp: time.Now().Unix(),
		list:     list.New(),
	}
}

type Set struct {
	id            string
	createTp      int64
	list          *list.List
	highest       uint16
	currentLen    uint16
	finalMetadata *Metadata
	nextProtocol  interface{}
	lastSeen      time.Time
}

func (t *Set) GetID() string {
	return t.id
}

func (t *Set) GetHighest() uint16 {
	return t.highest
}

func (t *Set) AddHighest(val uint16) uint16 {
	t.highest += val
	return t.highest
}

func (t *Set) SetHighest(val uint16) {
	t.highest = val
}

func (t *Set) GetCurrentLen() uint16 {
	return t.currentLen
}

func (t *Set) SetNextProtocol(proto interface{}) {
	t.nextProtocol = proto
}

func (t *Set) GetNextProtocol() interface{} {
	return t.nextProtocol
}

func (t *Set) AddCurrentLen(val uint16) uint16 {
	t.currentLen += val
	return t.currentLen
}

func (t *Set) CheckFinalMetadataExists() bool {
	return t.finalMetadata != nil
}

func (t *Set) SetFinalMetadata(metadata *Metadata) {
	t.finalMetadata = metadata
}

func (t *Set) GetFinalMetadata() *Metadata {
	return t.finalMetadata
}

func (t *Set) PushBack(v any) {
	t.list.PushBack(v)
}

func (t *Set) InsertBefore(v any, mark *list.Element) *list.Element {
	return t.list.InsertBefore(v, mark)
}

func (t *Set) IterElements(f func(elem *list.Element) bool) {
	for e := t.list.Front(); e != nil; e = e.Next() {
		if !f(e) {
			return
		}
	}
}
