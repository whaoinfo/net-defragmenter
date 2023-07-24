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
	//ErrResultTypeHandleNil
	ErrResultTypeNewPacket

	ErrResultIPV4NetworkLayerNil
	ErrResultConvIPV4
	ErrResultIPv4Serialize
	ErrResultIPV4NewPacket
	ErrResultIPV4HdrLenInsufficient

	ErrResultIPV6NetworkLayerNil
	ErrResultNoIPV6FragLayer
	ErrResultConvIPv6Frag
	ErrResultIPv6Serialize
	ErrResultTypeIPV6NewPacket
	ErrResultIPV6HdrLenInsufficient
	ErrResultIPV6FragHdrLenInsufficient

	//ErrResultTypeCollect
	//ErrResultTypeReassembly
)

const (
	ResultPacketProcessStepErr uint8 = iota
)
