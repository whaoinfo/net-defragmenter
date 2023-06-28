package net_defragmenter

import (
	"github.com/whaoinfo/net-defragmenter/definition"
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
	MaxCollectorsNum int
	MaxChannelCap    int
	TickerInterval   time.Duration
}

type ClassifierOption struct {
	MaxClassifiersNum int
}

type Option struct {
	FragmentTypes    []definition.FragmentType
	Interval         time.Duration
	CollectorOption  CollectorOption
	ClassifierOption ClassifierOption
}
