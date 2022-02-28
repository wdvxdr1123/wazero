package internalwasm

import "sync/atomic"

type referenceCounter struct {
	cnt int64
}

func (r *referenceCounter) inc() (newValue int64) {
	return atomic.AddInt64(&r.cnt, 1)
}

func (r *referenceCounter) dec() (newValue int64) {
	return atomic.AddInt64(&r.cnt, -1)
}

func newReferenceCounter() referenceCounter {
	return referenceCounter{cnt: 1}
}
