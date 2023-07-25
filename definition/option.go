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
	MaxFullPktQueueLen uint32
}

type CtrlApiServerOption struct {
	Enable bool
	Port   int
}

type StatsOption struct {
	Enable bool
}

type Option struct {
	CtrlApiServerOption CtrlApiServerOption
	StatsOption         StatsOption
	PickFragmentTypes   []FragmentType
	CollectorOption     CollectorOption
}
