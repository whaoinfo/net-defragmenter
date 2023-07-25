package definition

const (
	InitializeStatus int32 = iota
	InitializedStatus
	StartedStatus
	StoppedStatus
)

type ErrResultType uint16

const (
	NonErrResultType ErrResultType = iota
	ErrResultTypeNewPacket
	ErrResultSerializeLayers
	ErrResultFullPacketBufAppendBytes

	ErrResultIPV4HdrLenInsufficient

	ErrResultIPV6NetworkLayerNil
	ErrResultIPV6HdrLenInsufficient
	ErrResultIPV6FragHdrLenInsufficient
)

const (
	ResultPacketProcessStepErr uint8 = iota
)
