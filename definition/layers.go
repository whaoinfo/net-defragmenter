package definition

const (
	IPVersionLen = 1
)

const (
	EthDstLen  = 6
	EthSrcLen  = 6
	EthTypeLen = 2
	EthHdrLen  = EthDstLen + EthSrcLen + EthTypeLen
)

const (
	IPV4DifferentiatedSvcFieldLen = 1
	IPV4TotalLengthFieldLen       = 2
	IPV4IdentificationLen         = 2
	IPV4FlagsFlagsLen             = 2
	IPV4TimeToLiveLen             = 1
	IPV4ProtocolLen               = 1
	IPV4HeaderChecksumLen         = 2
	IPV4SourceAddressLen          = 4
	IPV4DestinationAddressLen     = 4
	IPV4HdrLen                    = IPVersionLen + IPV4DifferentiatedSvcFieldLen + IPV4TotalLengthFieldLen + IPV4IdentificationLen +
		IPV4FlagsFlagsLen + IPV4TimeToLiveLen + IPV4ProtocolLen + IPV4HeaderChecksumLen +
		IPV4SourceAddressLen + IPV4DestinationAddressLen
)

const (
	IPV6TrafficClassFlowLabelLen = 3
	IPV6PayloadLen               = 2
	IPV6NextHeaderLen            = 1
	IPV6HopLimitLen              = 1
	IPV6SrcAddrLen               = 16
	IPV6DstAddrLen               = 16
	IPV6HdrLen                   = IPVersionLen + IPV6TrafficClassFlowLabelLen + IPV6PayloadLen + IPV6NextHeaderLen +
		IPV6HopLimitLen + IPV6SrcAddrLen + IPV6DstAddrLen

	IPV6FragmentNextHeaderLen    = 1
	IPV6FragmentReservedOctetLen = 1
	IPV6FlagsFlagsLen            = 2
	IPV6FragHdrIdentOffsetLen    = 4
	IPV6FragmentHdrLen           = IPV6FragmentNextHeaderLen + IPV6FragmentReservedOctetLen + IPV6FlagsFlagsLen + IPV6FragHdrIdentOffsetLen

	IPV6FragLayerIdx = 2

	FragOffsetMulNum = 8
)

const (
	EthIPV4HdrLen = EthHdrLen + IPV4HdrLen
	EthIPV6HdrLen = EthHdrLen + IPV6HdrLen
)
