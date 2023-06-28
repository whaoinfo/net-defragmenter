package definition

type FragmentType int8

const (
	MinInvalidFragType FragmentType = iota - 1

	IPV4FragType
	IPV6FragType
	PFCPFragType

	MaxInvalidFragType
)
