//go:build !android && !ios

package trafficontrol

import (
	"os"

	"github.com/shirou/gopsutil/process"
)

func getMemory() uint64 {
	pid := os.Getpid()
	pc, err := process.NewProcess(int32(pid))
	if err == nil {
		memoryInfo, err := pc.MemoryInfo()
		if err == nil {
			return memoryInfo.RSS
		}
	}
	return 0
}
