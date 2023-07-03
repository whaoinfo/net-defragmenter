package definition

import (
	"time"
)

func NewOption(fns ...func(opt *Option)) *Option {
	opt := &Option{}
	for _, f := range fns {
		f(opt)
	}

	return opt
}

type IPV6WorkerOption struct {
	QueueLen int
	Interval time.Duration
	RWNum    int
}

type CollectorOption struct {
	MaxCollectorsNum   uint32
	MaxChannelCap      uint32
	MaxCompPktQueueLen uint32
	TickerInterval     time.Duration
}

type ClassifierOption struct {
	MaxClassifiersNum uint32
}

type Option struct {
	PickFragmentTypes []FragmentType
	CollectorOption   CollectorOption
	ClassifierOption  ClassifierOption
}
