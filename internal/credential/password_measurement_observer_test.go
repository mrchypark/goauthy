package credential

import (
	"sync"
	"time"
)

// Measurement-only ledger of call-boundary events. Callbacks never wait for a
// different operation, do I/O, or record credential material.
type passwordMeasurementObserver struct {
	mu                                                           sync.Mutex
	spans                                                        map[uint64]*passwordMeasurementSpan
	slots, slotWaiters, memoryWaiters, computing                 int
	reservedKiB, computingKiB                                    uint64
	PeakSlots, PeakSlotWaiters, PeakMemoryWaiters, PeakComputing int
	PeakReservedKiB, PeakComputingKiB                            uint64
}
type passwordMeasurementSpan struct {
	ID                                                                 uint64
	MemoryKiB                                                          uint32
	Outcome                                                            string
	Stage                                                              string
	Classified, SlotWait, Slot, MemoryWait, Memory, Start, Finish, End time.Time `json:"-"`
	SlotWaitMS, MemoryWaitMS, AdmissionToStartMS, ServiceMS, TotalMS   float64
}

func newPasswordMeasurementObserver() *passwordMeasurementObserver {
	return &passwordMeasurementObserver{spans: make(map[uint64]*passwordMeasurementSpan)}
}
func (o *passwordMeasurementObserver) observe(e passwordWorkEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.spans[e.ID]
	if s == nil {
		s = &passwordMeasurementSpan{ID: e.ID, MemoryKiB: e.MemoryKiB, Outcome: "ok"}
		o.spans[e.ID] = s
	}
	switch e.Stage {
	case "classified":
		s.Classified = e.At
	case "slot-wait":
		s.SlotWait = e.At
		o.slotWaiters++
	case "slot":
		s.Slot = e.At
		o.slotWaiters--
		o.slots++
	case "memory-wait":
		s.MemoryWait = e.At
		o.memoryWaiters++
	case "memory":
		s.Memory = e.At
		o.memoryWaiters--
		o.reservedKiB += uint64(e.MemoryKiB)
	case "start":
		s.Start = e.At
		o.computing++
		o.computingKiB += uint64(e.MemoryKiB)
	case "finish":
		s.Finish = e.At
		o.computing--
		o.computingKiB -= uint64(e.MemoryKiB)
		s.Outcome = e.Outcome
	case "memory-release":
		o.reservedKiB -= uint64(e.MemoryKiB)
	case "slot-release":
		o.slots--
	case "release":
		s.End = e.At
	case "reject-slot":
		if s.Slot.IsZero() && !s.SlotWait.IsZero() {
			o.slotWaiters--
		}
		s.End = e.At
		s.Outcome = e.Outcome
		s.Stage = e.Stage
	case "reject-memory":
		if s.Memory.IsZero() && !s.MemoryWait.IsZero() {
			o.memoryWaiters--
		}
		s.End = e.At
		s.Outcome = e.Outcome
		s.Stage = e.Stage
	}
	o.PeakSlots = max(o.PeakSlots, o.slots)
	o.PeakSlotWaiters = max(o.PeakSlotWaiters, o.slotWaiters)
	o.PeakMemoryWaiters = max(o.PeakMemoryWaiters, o.memoryWaiters)
	o.PeakComputing = max(o.PeakComputing, o.computing)
	o.PeakReservedKiB = max(o.PeakReservedKiB, o.reservedKiB)
	o.PeakComputingKiB = max(o.PeakComputingKiB, o.computingKiB)
}
func (o *passwordMeasurementObserver) results() []passwordMeasurementSpan {
	result := make([]passwordMeasurementSpan, 0, len(o.spans))
	ms := func(a, b time.Time) float64 {
		if a.IsZero() || b.IsZero() {
			return 0
		}
		return float64(b.Sub(a)) / float64(time.Millisecond)
	}
	for id := uint64(1); id <= uint64(len(o.spans)); id++ {
		s := *o.spans[id]
		slotEnd := s.Slot
		if slotEnd.IsZero() {
			slotEnd = s.End
		}
		memoryEnd := s.Memory
		if memoryEnd.IsZero() {
			memoryEnd = s.End
		}
		s.SlotWaitMS = ms(s.SlotWait, slotEnd)
		s.MemoryWaitMS = ms(s.MemoryWait, memoryEnd)
		s.AdmissionToStartMS = ms(s.Memory, s.Start)
		s.ServiceMS = ms(s.Start, s.Finish)
		s.TotalMS = ms(s.Classified, s.End)
		result = append(result, s)
	}
	return result
}
