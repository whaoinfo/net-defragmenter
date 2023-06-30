package linkqueue

import (
	"container/list"
	"sync"
)

func NewLinkQueue() *LinkQueue {
	return &LinkQueue{
		list: list.New(),
	}
}

type LinkQueue struct {
	mutex sync.RWMutex
	list  *list.List
}

func (t *LinkQueue) SafetyGetLen() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.list.Len()
}

func (t *LinkQueue) PutValue(value interface{}) {
	t.list.PushFront(value)
}

func (t *LinkQueue) SafetyPutValue(value interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.PutValue(value)
}

func (t *LinkQueue) SafetyPutValues(values ...interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, value := range values {
		t.list.PushBack(value)
	}
}

func (t *LinkQueue) SafetyPutValuesToHead(values ...interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, value := range values {
		t.list.PushFront(value)
	}
}

func (t *LinkQueue) PopValue() (interface{}, bool) {
	valuesLen := t.list.Len()
	if valuesLen <= 0 {
		return nil, false
	}
	elem := t.list.Front()
	t.list.Remove(elem)
	return elem.Value, true
}

func (t *LinkQueue) SafetyPopValue() (interface{}, bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.PopValue()
}

func (t *LinkQueue) SafetyPopValues(count int) []interface{} {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	valuesLen := t.list.Len()
	if valuesLen <= 0 {
		return nil
	}

	if count > valuesLen {
		count = valuesLen
	}

	retValues := make([]interface{}, 0, count)
	for i := 0; i < count; i++ {
		elem := t.list.Front()
		t.list.Remove(elem)
		retValues = append(retValues, elem.Value)
	}

	return retValues
}

func (t *LinkQueue) ForeachFromFront(f func(elem *list.Element) bool) {
	elem := t.list.Front()
	if elem == nil {
		return
	}

	for {
		if f(elem) {
			return
		}
		elem = elem.Next()
		if elem == nil {
			return
		}
	}
}

func (t *LinkQueue) SafetyForeachFromFront(f func(elem *list.Element) bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	t.ForeachFromFront(f)
}

func (t *LinkQueue) SafetyRemoveValues(values []*list.Element) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, val := range values {
		t.list.Remove(val)
	}

}

func (t *LinkQueue) SafetyCheckAndRemoveValues(f func(elem *list.Element) bool) []interface{} {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	var delElems []*list.Element
	var retValues []interface{}
	elem := t.list.Front()
	if elem == nil {
		return retValues
	}

	for {
		if f(elem) {
			delElems = append(delElems, elem)
		}
		elem = elem.Next()
		if elem == nil {
			break
		}
	}

	for _, delElem := range delElems {
		retValues = append(retValues, t.list.Remove(delElem))
	}

	return retValues
}
