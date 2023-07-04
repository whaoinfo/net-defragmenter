package libstats

import (
	"fmt"
	"runtime"
	"time"
)

const (
	kbSize = 1024
	mbSize = kbSize * 1024
)

type MemoryStatus struct {
	Alloc         string
	TotalAlloc    string
	Sys           string
	Mallocs       uint64
	Frees         uint64
	HeapAlloc     string
	HeapSys       string
	HeapInuse     string
	HeapReleased  string
	NextGC        string
	LastGC        string
	GCCPUFraction float64
	NumForcedGC   uint32
}

func CollectMemoryStatus() MemoryStatus {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	stats := MemoryStatus{}
	stats.Alloc = fmt.Sprintf("Alloc MBs=%v, KBs=%v, Bs=%v", ms.Alloc/uint64(mbSize), ms.Alloc/kbSize, ms.Alloc)
	stats.TotalAlloc = fmt.Sprintf("TotalAlloc MBs=%v", ms.TotalAlloc/uint64(mbSize))
	stats.Sys = fmt.Sprintf("TotalAlloc MBs=%v", ms.Sys/uint64(mbSize))
	stats.HeapAlloc = fmt.Sprintf("HeapAlloc MBs=%v", ms.HeapAlloc/uint64(mbSize))
	stats.HeapSys = fmt.Sprintf("HeapSys MBs=%v", ms.HeapSys/uint64(mbSize))
	stats.HeapInuse = fmt.Sprintf("HeapInuse MBs=%v", ms.HeapInuse/uint64(mbSize))
	stats.HeapReleased = fmt.Sprintf("HeapReleased MBs=%v", ms.HeapReleased/uint64(mbSize))

	stats.Mallocs = ms.Mallocs
	stats.Frees = ms.Frees

	stats.GCCPUFraction = ms.GCCPUFraction

	stats.LastGC = time.UnixMicro(int64(ms.LastGC) / int64(time.Microsecond)).String()
	stats.NextGC = fmt.Sprintf("NextGC MBs=%v", ms.NextGC/uint64(mbSize))
	stats.NumForcedGC = ms.NumForcedGC

	return stats
}
