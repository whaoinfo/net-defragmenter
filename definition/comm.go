package definition

import "github.com/whaoinfo/net-defragmenter/monition"

const (
	InitializeStatus int32 = iota
	InitializedStatus
	StartedStatus
	StoppedStatus
)

type ManagerProxy interface {
	GetMonitor() *monition.Monitor
}
