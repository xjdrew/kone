//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	anySize                  = 1
	maxDNSSuffixStringLength = 256
	maxDHCPv6DUIDLength      = 130
	ifMaxStringSize          = 256
	ifMaxPhysAddressLength   = 32
)

// AddressFamily enumeration specifies protocol family and is one of the windows.AF_* constants.
type AddressFamily uint16

// IPAAFlags enumeration describes adapter addresses flags
// https://docs.microsoft.com/en-us/windows/desktop/api/iptypes/ns-iptypes-_ip_adapter_addresses_lh
type IPAAFlags uint32

const (
	IPAAFlagDdnsEnabled IPAAFlags = 1 << iota
	IPAAFlagRegisterAdapterSuffix
	IPAAFlagDhcpv4Enabled
	IPAAFlagReceiveOnly
	IPAAFlagNoMulticast
	IPAAFlagIpv6OtherStatefulConfig
	IPAAFlagNetbiosOverTcpipEnabled
	IPAAFlagIpv4Enabled
	IPAAFlagIpv6Enabled
	IPAAFlagIpv6ManagedAddressConfigurationSupported
)

// IfOperStatus enumeration specifies the operational status of an interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-if_oper_status
type IfOperStatus uint32

const (
	IfOperStatusUp IfOperStatus = iota + 1
	IfOperStatusDown
	IfOperStatusTesting
	IfOperStatusUnknown
	IfOperStatusDormant
	IfOperStatusNotPresent
	IfOperStatusLowerLayerDown
)

// IfType enumeration specifies interface type.
type IfType uint32

const (
	IfTypeOther                         IfType = 1 // None of the below
	IfTypeRegular1822                   IfType = 2
	IfTypeHdh1822                       IfType = 3
	IfTypeDdnX25                        IfType = 4
	IfTypeRfc877X25                     IfType = 5
	IfTypeEthernetCSMACD                IfType = 6
	IfTypeISO88023CSMACD                IfType = 7
	IfTypeISO88024Tokenbus              IfType = 8
	IfTypeISO88025Tokenring             IfType = 9
	IfTypeISO88026Man                   IfType = 10
	IfTypeStarlan                       IfType = 11
	IfTypeProteon10Mbit                 IfType = 12
	IfTypeProteon80Mbit                 IfType = 13
	IfTypeHyperchannel                  IfType = 14
	IfTypeFddi                          IfType = 15
	IfTypeLapB                          IfType = 16
	IfTypeSdlc                          IfType = 17
	IfTypeDs1                           IfType = 18 // DS1-MIB
	IfTypeE1                            IfType = 19 // Obsolete; see DS1-MIB
	IfTypeBasicISDN                     IfType = 20
	IfTypePrimaryISDN                   IfType = 21
	IfTypePropPoint2PointSerial         IfType = 22 // proprietary serial
	IfTypePPP                           IfType = 23
	IfTypeSoftwareLoopback              IfType = 24
	IfTypeEon                           IfType = 25 // CLNP over IP
	IfTypeEthernet3Mbit                 IfType = 26
	IfTypeNsip                          IfType = 27 // XNS over IP
	IfTypeSlip                          IfType = 28 // Generic Slip
	IfTypeUltra                         IfType = 29 // ULTRA Technologies
	IfTypeDs3                           IfType = 30 // DS3-MIB
	IfTypeSip                           IfType = 31 // SMDS, coffee
	IfTypeFramerelay                    IfType = 32 // DTE only
	IfTypeRs232                         IfType = 33
	IfTypePara                          IfType = 34 // Parallel port
	IfTypeArcnet                        IfType = 35
	IfTypeArcnetPlus                    IfType = 36
	IfTypeAtm                           IfType = 37 // ATM cells
	IfTypeMioX25                        IfType = 38
	IfTypeSonet                         IfType = 39 // SONET or SDH
	IfTypeX25Ple                        IfType = 40
	IfTypeIso88022LLC                   IfType = 41
	IfTypeLocaltalk                     IfType = 42
	IfTypeSmdsDxi                       IfType = 43
	IfTypeFramerelayService             IfType = 44 // FRNETSERV-MIB
	IfTypeV35                           IfType = 45
	IfTypeHssi                          IfType = 46
	IfTypeHippi                         IfType = 47
	IfTypeModem                         IfType = 48 // Generic Modem
	IfTypeAal5                          IfType = 49 // AAL5 over ATM
	IfTypeSonetPath                     IfType = 50
	IfTypeSonetVt                       IfType = 51
	IfTypeSmdsIcip                      IfType = 52 // SMDS InterCarrier Interface
	IfTypePropVirtual                   IfType = 53 // Proprietary virtual/internal
	IfTypePropMultiplexor               IfType = 54 // Proprietary multiplexing
	IfTypeIEEE80212                     IfType = 55 // 100BaseVG
	IfTypeFibrechannel                  IfType = 56
	IfTypeHippiinterface                IfType = 57
	IfTypeFramerelayInterconnect        IfType = 58 // Obsolete, use 32 or 44
	IfTypeAflane8023                    IfType = 59 // ATM Emulated LAN for 802.3
	IfTypeAflane8025                    IfType = 60 // ATM Emulated LAN for 802.5
	IfTypeCctemul                       IfType = 61 // ATM Emulated circuit
	IfTypeFastether                     IfType = 62 // Fast Ethernet (100BaseT)
	IfTypeISDN                          IfType = 63 // ISDN and X.25
	IfTypeV11                           IfType = 64 // CCITT V.11/X.21
	IfTypeV36                           IfType = 65 // CCITT V.36
	IfTypeG703_64k                      IfType = 66 // CCITT G703 at 64Kbps
	IfTypeG703_2mb                      IfType = 67 // Obsolete; see DS1-MIB
	IfTypeQllc                          IfType = 68 // SNA QLLC
	IfTypeFastetherFX                   IfType = 69 // Fast Ethernet (100BaseFX)
	IfTypeChannel                       IfType = 70
	IfTypeIEEE80211                     IfType = 71  // Radio spread spectrum
	IfTypeIBM370parchan                 IfType = 72  // IBM System 360/370 OEMI Channel
	IfTypeEscon                         IfType = 73  // IBM Enterprise Systems Connection
	IfTypeDlsw                          IfType = 74  // Data Link Switching
	IfTypeISDNS                         IfType = 75  // ISDN S/T interface
	IfTypeISDNU                         IfType = 76  // ISDN U interface
	IfTypeLapD                          IfType = 77  // Link Access Protocol D
	IfTypeIpswitch                      IfType = 78  // IP Switching Objects
	IfTypeRsrb                          IfType = 79  // Remote Source Route Bridging
	IfTypeAtmLogical                    IfType = 80  // ATM Logical Port
	IfTypeDs0                           IfType = 81  // Digital Signal Level 0
	IfTypeDs0Bundle                     IfType = 82  // Group of ds0s on the same ds1
	IfTypeBsc                           IfType = 83  // Bisynchronous Protocol
	IfTypeAsync                         IfType = 84  // Asynchronous Protocol
	IfTypeCnr                           IfType = 85  // Combat Net Radio
	IfTypeIso88025rDtr                  IfType = 86  // ISO 802.5r DTR
	IfTypeEplrs                         IfType = 87  // Ext Pos Loc Report Sys
	IfTypeArap                          IfType = 88  // Appletalk Remote Access Protocol
	IfTypePropCnls                      IfType = 89  // Proprietary Connectionless Proto
	IfTypeHostpad                       IfType = 90  // CCITT-ITU X.29 PAD Protocol
	IfTypeTermpad                       IfType = 91  // CCITT-ITU X.3 PAD Facility
	IfTypeFramerelayMpi                 IfType = 92  // Multiproto Interconnect over FR
	IfTypeX213                          IfType = 93  // CCITT-ITU X213
	IfTypeAdsl                          IfType = 94  // Asymmetric Digital Subscrbr Loop
	IfTypeRadsl                         IfType = 95  // Rate-Adapt Digital Subscrbr Loop
	IfTypeSdsl                          IfType = 96  // Symmetric Digital Subscriber Loop
	IfTypeVdsl                          IfType = 97  // Very H-Speed Digital Subscrb Loop
	IfTypeIso88025Crfprint              IfType = 98  // ISO 802.5 CRFP
	IfTypeMyrinet                       IfType = 99  // Myricom Myrinet
	IfTypeVoiceEm                       IfType = 100 // Voice recEive and transMit
	IfTypeVoiceFxo                      IfType = 101 // Voice Foreign Exchange Office
	IfTypeVoiceFxs                      IfType = 102 // Voice Foreign Exchange Station
	IfTypeVoiceEncap                    IfType = 103 // Voice encapsulation
	IfTypeVoiceOverip                   IfType = 104 // Voice over IP encapsulation
	IfTypeAtmDxi                        IfType = 105 // ATM DXI
	IfTypeAtmFuni                       IfType = 106 // ATM FUNI
	IfTypeAtmIma                        IfType = 107 // ATM IMA
	IfTypePPPmultilinkbundle            IfType = 108 // PPP Multilink Bundle
	IfTypeIpoverCdlc                    IfType = 109 // IBM ipOverCdlc
	IfTypeIpoverClaw                    IfType = 110 // IBM Common Link Access to Workstn
	IfTypeStacktostack                  IfType = 111 // IBM stackToStack
	IfTypeVirtualipaddress              IfType = 112 // IBM VIPA
	IfTypeMpc                           IfType = 113 // IBM multi-proto channel support
	IfTypeIpoverAtm                     IfType = 114 // IBM ipOverAtm
	IfTypeIso88025Fiber                 IfType = 115 // ISO 802.5j Fiber Token Ring
	IfTypeTdlc                          IfType = 116 // IBM twinaxial data link control
	IfTypeGigabitethernet               IfType = 117
	IfTypeHdlc                          IfType = 118
	IfTypeLapF                          IfType = 119
	IfTypeV37                           IfType = 120
	IfTypeX25Mlp                        IfType = 121 // Multi-Link Protocol
	IfTypeX25Huntgroup                  IfType = 122 // X.25 Hunt Group
	IfTypeTransphdlc                    IfType = 123
	IfTypeInterleave                    IfType = 124 // Interleave channel
	IfTypeFast                          IfType = 125 // Fast channel
	IfTypeIP                            IfType = 126 // IP (for APPN HPR in IP networks)
	IfTypeDocscableMaclayer             IfType = 127 // CATV Mac Layer
	IfTypeDocscableDownstream           IfType = 128 // CATV Downstream interface
	IfTypeDocscableUpstream             IfType = 129 // CATV Upstream interface
	IfTypeA12mppswitch                  IfType = 130 // Avalon Parallel Processor
	IfTypeTunnel                        IfType = 131 // Encapsulation interface
	IfTypeCoffee                        IfType = 132 // Coffee pot
	IfTypeCes                           IfType = 133 // Circuit Emulation Service
	IfTypeAtmSubinterface               IfType = 134 // ATM Sub Interface
	IfTypeL2Vlan                        IfType = 135 // Layer 2 Virtual LAN using 802.1Q
	IfTypeL3Ipvlan                      IfType = 136 // Layer 3 Virtual LAN using IP
	IfTypeL3Ipxvlan                     IfType = 137 // Layer 3 Virtual LAN using IPX
	IfTypeDigitalpowerline              IfType = 138 // IP over Power Lines
	IfTypeMediamailoverip               IfType = 139 // Multimedia Mail over IP
	IfTypeDtm                           IfType = 140 // Dynamic syncronous Transfer Mode
	IfTypeDcn                           IfType = 141 // Data Communications Network
	IfTypeIpforward                     IfType = 142 // IP Forwarding Interface
	IfTypeMsdsl                         IfType = 143 // Multi-rate Symmetric DSL
	IfTypeIEEE1394                      IfType = 144 // IEEE1394 High Perf Serial Bus
	IfTypeIfGsn                         IfType = 145
	IfTypeDvbrccMaclayer                IfType = 146
	IfTypeDvbrccDownstream              IfType = 147
	IfTypeDvbrccUpstream                IfType = 148
	IfTypeAtmVirtual                    IfType = 149
	IfTypeMplsTunnel                    IfType = 150
	IfTypeSrp                           IfType = 151
	IfTypeVoiceoveratm                  IfType = 152
	IfTypeVoiceoverframerelay           IfType = 153
	IfTypeIdsl                          IfType = 154
	IfTypeCompositelink                 IfType = 155
	IfTypeSs7Siglink                    IfType = 156
	IfTypePropWirelessP2P               IfType = 157
	IfTypeFrForward                     IfType = 158
	IfTypeRfc1483                       IfType = 159
	IfTypeUsb                           IfType = 160
	IfTypeIEEE8023adLag                 IfType = 161
	IfTypeBgpPolicyAccounting           IfType = 162
	IfTypeFrf16MfrBundle                IfType = 163
	IfTypeH323Gatekeeper                IfType = 164
	IfTypeH323Proxy                     IfType = 165
	IfTypeMpls                          IfType = 166
	IfTypeMfSiglink                     IfType = 167
	IfTypeHdsl2                         IfType = 168
	IfTypeShdsl                         IfType = 169
	IfTypeDs1Fdl                        IfType = 170
	IfTypePos                           IfType = 171
	IfTypeDvbAsiIn                      IfType = 172
	IfTypeDvbAsiOut                     IfType = 173
	IfTypePlc                           IfType = 174
	IfTypeNfas                          IfType = 175
	IfTypeTr008                         IfType = 176
	IfTypeGr303Rdt                      IfType = 177
	IfTypeGr303Idt                      IfType = 178
	IfTypeIsup                          IfType = 179
	IfTypePropDocsWirelessMaclayer      IfType = 180
	IfTypePropDocsWirelessDownstream    IfType = 181
	IfTypePropDocsWirelessUpstream      IfType = 182
	IfTypeHiperlan2                     IfType = 183
	IfTypePropBwaP2MP                   IfType = 184
	IfTypeSonetOverheadChannel          IfType = 185
	IfTypeDigitalWrapperOverheadChannel IfType = 186
	IfTypeAal2                          IfType = 187
	IfTypeRadioMac                      IfType = 188
	IfTypeAtmRadio                      IfType = 189
	IfTypeImt                           IfType = 190
	IfTypeMvl                           IfType = 191
	IfTypeReachDsl                      IfType = 192
	IfTypeFrDlciEndpt                   IfType = 193
	IfTypeAtmVciEndpt                   IfType = 194
	IfTypeOpticalChannel                IfType = 195
	IfTypeOpticalTransport              IfType = 196
	IfTypeIEEE80216Wman                 IfType = 237
	IfTypeWwanpp                        IfType = 243 // WWAN devices based on GSM technology
	IfTypeWwanpp2                       IfType = 244 // WWAN devices based on CDMA technology
	IfTypeIEEE802154                    IfType = 259 // IEEE 802.15.4 WPAN interface
	IfTypeXboxWireless                  IfType = 281
)

// MibIfEntryLevel enumeration specifies level of interface information to retrieve in GetIfTable2Ex function call.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getifentry2ex
type MibIfEntryLevel uint32

const (
	MibIfEntryNormal                  MibIfEntryLevel = 0
	MibIfEntryNormalWithoutStatistics MibIfEntryLevel = 2
)

// NdisMedium enumeration type identifies the medium types that NDIS drivers support.
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddndis/ne-ntddndis-_ndis_medium
type NdisMedium uint32

const (
	NdisMedium802_3 NdisMedium = iota
	NdisMedium802_5
	NdisMediumFddi
	NdisMediumWan
	NdisMediumLocalTalk
	NdisMediumDix // defined for convenience, not a real medium
	NdisMediumArcnetRaw
	NdisMediumArcnet878_2
	NdisMediumAtm
	NdisMediumWirelessWan
	NdisMediumIrda
	NdisMediumBpc
	NdisMediumCoWan
	NdisMedium1394
	NdisMediumInfiniBand
	NdisMediumTunnel
	NdisMediumNative802_11
	NdisMediumLoopback
	NdisMediumWiMAX
	NdisMediumIP
	NdisMediumMax
)

// NdisPhysicalMedium describes NDIS physical medium type.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_if_row2
type NdisPhysicalMedium uint32

const (
	NdisPhysicalMediumUnspecified NdisPhysicalMedium = iota
	NdisPhysicalMediumWirelessLan
	NdisPhysicalMediumCableModem
	NdisPhysicalMediumPhoneLine
	NdisPhysicalMediumPowerLine
	NdisPhysicalMediumDSL // includes ADSL and UADSL (G.Lite)
	NdisPhysicalMediumFibreChannel
	NdisPhysicalMedium1394
	NdisPhysicalMediumWirelessWan
	NdisPhysicalMediumNative802_11
	NdisPhysicalMediumBluetooth
	NdisPhysicalMediumInfiniband
	NdisPhysicalMediumWiMax
	NdisPhysicalMediumUWB
	NdisPhysicalMedium802_3
	NdisPhysicalMedium802_5
	NdisPhysicalMediumIrda
	NdisPhysicalMediumWiredWAN
	NdisPhysicalMediumWiredCoWan
	NdisPhysicalMediumOther
	NdisPhysicalMediumNative802_15_4
	NdisPhysicalMediumMax
)

// NetIfAccessType enumeration type specifies the NDIS network interface access type.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-_net_if_access_type
type NetIfAccessType uint32

const (
	NetIfAccessLoopback NetIfAccessType = iota + 1
	NetIfAccessBroadcast
	NetIfAccessPointToPoint
	NetIfAccessPointToMultiPoint
	NetIfAccessMax
)

// NetIfAdminStatus enumeration type specifies the NDIS network interface administrative status, as described in RFC 2863.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-net_if_admin_status
type NetIfAdminStatus uint32

const (
	NetIfAdminStatusUp NetIfAdminStatus = iota + 1
	NetIfAdminStatusDown
	NetIfAdminStatusTesting
)

// NetIfConnectionType enumeration type specifies the NDIS network interface connection type.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-_net_if_connection_type
type NetIfConnectionType uint32

const (
	NetIfConnectionDedicated NetIfConnectionType = iota + 1
	NetIfConnectionPassive
	NetIfConnectionDemand
	NetIfConnectionMaximum
)

// NetIfDirectionType enumeration type specifies the NDIS network interface direction type.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-net_if_direction_type
type NetIfDirectionType uint32

const (
	NetIfDirectionSendReceive NetIfDirectionType = iota
	NetIfDirectionSendOnly
	NetIfDirectionReceiveOnly
	NetIfDirectionMaximum
)

// NetIfMediaConnectState enumeration type specifies the NDIS network interface connection state.
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-_net_if_media_connect_state
type NetIfMediaConnectState uint32

const (
	MediaConnectStateUnknown NetIfMediaConnectState = iota
	MediaConnectStateConnected
	MediaConnectStateDisconnected
)

// DadState enumeration specifies information about the duplicate address detection (DAD) state for an IPv4 or IPv6 address.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_dad_state
type DadState uint32

const (
	DadStateInvalid DadState = iota
	DadStateTentative
	DadStateDuplicate
	DadStateDeprecated
	DadStatePreferred
)

// PrefixOrigin enumeration specifies the origin of an IPv4 or IPv6 address prefix, and is used with the IP_ADAPTER_UNICAST_ADDRESS structure.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_prefix_origin
type PrefixOrigin uint32

const (
	PrefixOriginOther PrefixOrigin = iota
	PrefixOriginManual
	PrefixOriginWellKnown
	PrefixOriginDHCP
	PrefixOriginRouterAdvertisement
	PrefixOriginUnchanged = 1 << 4
)

// LinkLocalAddressBehavior enumeration type defines the link local address behavior.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-_nl_link_local_address_behavior
type LinkLocalAddressBehavior int32

const (
	LinkLocalAddressAlwaysOff LinkLocalAddressBehavior = iota // Never use link locals.
	LinkLocalAddressDelayed                                   // Use link locals only if no other addresses. (default for IPv4). Legacy mapping: IPAutoconfigurationEnabled.
	LinkLocalAddressAlwaysOn                                  // Always use link locals (default for IPv6).
	LinkLocalAddressUnchanged = -1
)

// OffloadRod enumeration specifies a set of flags that indicate the offload capabilities for an IP interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ns-nldef-_nl_interface_offload_rod
type OffloadRod uint8

const (
	ChecksumSupported OffloadRod = 1 << iota
	OptionsSupported
	DatagramChecksumSupported
	StreamChecksumSupported
	StreamOptionsSupported
	FastPathCompatible
	LargeSendOffloadSupported
	GiantSendOffloadSupported
)

// RouteOrigin enumeration type defines the origin of the IP route.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_route_origin
type RouteOrigin uint32

const (
	RouteOriginManual RouteOrigin = iota
	RouteOriginWellKnown
	RouteOriginDHCP
	RouteOriginRouterAdvertisement
	RouteOrigin6to4
)

// RouteProtocol enumeration type defines the routing mechanism that an IP route was added with, as described in RFC 4292.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_route_protocol
type RouteProtocol uint32

const (
	RouteProtocolOther RouteProtocol = iota + 1
	RouteProtocolLocal
	RouteProtocolNetMgmt
	RouteProtocolIcmp
	RouteProtocolEgp
	RouteProtocolGgp
	RouteProtocolHello
	RouteProtocolRip
	RouteProtocolIsIs
	RouteProtocolEsIs
	RouteProtocolCisco
	RouteProtocolBbn
	RouteProtocolOspf
	RouteProtocolBgp
	RouteProtocolIdpr
	RouteProtocolEigrp
	RouteProtocolDvmrp
	RouteProtocolRpl
	RouteProtocolDHCP
	RouteProtocolNTAutostatic   = 10002
	RouteProtocolNTStatic       = 10006
	RouteProtocolNTStaticNonDOD = 10007
)

// RouterDiscoveryBehavior enumeration type defines the router discovery behavior, as described in RFC 2461.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-_nl_router_discovery_behavior
type RouterDiscoveryBehavior int32

const (
	RouterDiscoveryDisabled RouterDiscoveryBehavior = iota
	RouterDiscoveryEnabled
	RouterDiscoveryDHCP
	RouterDiscoveryUnchanged = -1
)

// SuffixOrigin enumeration specifies the origin of an IPv4 or IPv6 address suffix, and is used with the IP_ADAPTER_UNICAST_ADDRESS structure.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_suffix_origin
type SuffixOrigin uint32

const (
	SuffixOriginOther SuffixOrigin = iota
	SuffixOriginManual
	SuffixOriginWellKnown
	SuffixOriginDHCP
	SuffixOriginLinkLayerAddress
	SuffixOriginRandom
	SuffixOriginUnchanged = 1 << 4
)

// MibNotificationType enumeration defines the notification type passed to a callback function when a notification occurs.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ne-netioapi-_mib_notification_type
type MibNotificationType uint32

const (
	MibParameterNotification MibNotificationType = iota // Parameter change
	MibAddInstance                                      // Addition
	MibDeleteInstance                                   // Deletion
	MibInitialNotification                              // Initial notification
)

type ChangeCallback interface {
	Unregister() error
}

// TunnelType enumeration type defines the encapsulation method used by a tunnel, as described by the Internet Assigned Names Authority (IANA).
// https://docs.microsoft.com/en-us/windows/desktop/api/ifdef/ne-ifdef-tunnel_type
type TunnelType uint32

const (
	TunnelTypeNone    TunnelType = 0
	TunnelTypeOther   TunnelType = 1
	TunnelTypeDirect  TunnelType = 2
	TunnelType6to4    TunnelType = 11
	TunnelTypeIsatap  TunnelType = 13
	TunnelTypeTeredo  TunnelType = 14
	TunnelTypeIPHTTPS TunnelType = 15
)

// InterfaceAndOperStatusFlags enumeration type defines interface and operation flags
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_if_row2
type InterfaceAndOperStatusFlags uint8

const (
	IAOSFHardwareInterface InterfaceAndOperStatusFlags = 1 << iota
	IAOSFFilterInterface
	IAOSFConnectorPresent
	IAOSFNotAuthenticated
	IAOSFNotMediaConnected
	IAOSFPaused
	IAOSFLowPower
	IAOSFEndPointInterface
)

// GAAFlags enumeration defines flags used in GetAdaptersAddresses calls
// https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
type GAAFlags uint32

const (
	GAAFlagSkipUnicast GAAFlags = 1 << iota
	GAAFlagSkipAnycast
	GAAFlagSkipMulticast
	GAAFlagSkipDNSServer
	GAAFlagIncludePrefix
	GAAFlagSkipFriendlyName
	GAAFlagIncludeWinsInfo
	GAAFlagIncludeGateways
	GAAFlagIncludeAllInterfaces
	GAAFlagIncludeAllCompartments
	GAAFlagIncludeTunnelBindingOrder
	GAAFlagSkipDNSInfo

	GAAFlagDefault    GAAFlags = 0
	GAAFlagSkipAll             = GAAFlagSkipUnicast | GAAFlagSkipAnycast | GAAFlagSkipMulticast | GAAFlagSkipDNSServer | GAAFlagSkipFriendlyName | GAAFlagSkipDNSInfo
	GAAFlagIncludeAll          = GAAFlagIncludePrefix | GAAFlagIncludeWinsInfo | GAAFlagIncludeGateways | GAAFlagIncludeAllInterfaces | GAAFlagIncludeAllCompartments | GAAFlagIncludeTunnelBindingOrder
)

// ScopeLevel enumeration is used with the IP_ADAPTER_ADDRESSES structure to identify scope levels for IPv6 addresses.
// https://docs.microsoft.com/en-us/windows/desktop/api/ws2def/ne-ws2def-scope_level
type ScopeLevel uint32

const (
	ScopeLevelInterface    ScopeLevel = 1
	ScopeLevelLink         ScopeLevel = 2
	ScopeLevelSubnet       ScopeLevel = 3
	ScopeLevelAdmin        ScopeLevel = 4
	ScopeLevelSite         ScopeLevel = 5
	ScopeLevelOrganization ScopeLevel = 8
	ScopeLevelGlobal       ScopeLevel = 14
	ScopeLevelCount        ScopeLevel = 16
)

// RouteData structure describes a route to add
type RouteData struct {
	Destination netip.Prefix
	NextHop     netip.Addr
	Metric      uint32
}

func (routeData *RouteData) String() string {
	return fmt.Sprintf("%+v", *routeData)
}

// IPAdapterDNSSuffix structure stores a DNS suffix in a linked list of DNS suffixes for a particular adapter.
// https://docs.microsoft.com/en-us/windows/desktop/api/iptypes/ns-iptypes-_ip_adapter_dns_suffix
type IPAdapterDNSSuffix struct {
	Next *IPAdapterDNSSuffix
	str  [maxDNSSuffixStringLength]uint16
}

// String method returns the DNS suffix for this DNS suffix entry.
func (obj *IPAdapterDNSSuffix) String() string {
	return windows.UTF16ToString(obj.str[:])
}

// AdapterName method returns the name of the adapter with which these addresses are associated.
// Unlike an adapter's friendly name, the adapter name returned by AdapterName is permanent and cannot be modified by the user.
func (addr *IPAdapterAddresses) AdapterName() string {
	return windows.BytePtrToString(addr.adapterName)
}

// DNSSuffix method returns adapter DNS suffix associated with this adapter.
func (addr *IPAdapterAddresses) DNSSuffix() string {
	if addr.dnsSuffix == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.dnsSuffix)
}

// Description method returns description for the adapter.
func (addr *IPAdapterAddresses) Description() string {
	if addr.description == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.description)
}

// FriendlyName method returns a user-friendly name for the adapter. For example: "Local Area Connection 1."
// This name appears in contexts such as the ipconfig command line program and the Connection folder.
func (addr *IPAdapterAddresses) FriendlyName() string {
	if addr.friendlyName == nil {
		return ""
	}
	return windows.UTF16PtrToString(addr.friendlyName)
}

// PhysicalAddress method returns the Media Access Control (MAC) address for the adapter.
// For example, on an Ethernet network this member would specify the Ethernet hardware address.
func (addr *IPAdapterAddresses) PhysicalAddress() []byte {
	return addr.physicalAddress[:addr.physicalAddressLength]
}

// DHCPv6ClientDUID method returns the DHCP unique identifier (DUID) for the DHCPv6 client.
// This information is only applicable to an IPv6 adapter address configured using DHCPv6.
func (addr *IPAdapterAddresses) DHCPv6ClientDUID() []byte {
	return addr.dhcpv6ClientDUID[:addr.dhcpv6ClientDUIDLength]
}

// Init method initializes the members of an MIB_IPINTERFACE_ROW entry with default values.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-initializeipinterfaceentry
func (row *MibIPInterfaceRow) Init() {
	initializeIPInterfaceEntry(row)
}

// get method retrieves IP information for the specified interface on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipinterfaceentry
func (row *MibIPInterfaceRow) get() error {
	if err := getIPInterfaceEntry(row); err != nil {
		return err
	}

	// Patch that fixes SitePrefixLength issue
	// https://stackoverflow.com/questions/54857292/setipinterfaceentry-returns-error-invalid-parameter?noredirect=1
	switch row.Family {
	case windows.AF_INET:
		if row.SitePrefixLength > 32 {
			row.SitePrefixLength = 0
		}
	case windows.AF_INET6:
		if row.SitePrefixLength > 128 {
			row.SitePrefixLength = 128
		}
	}

	return nil
}

// Set method sets the properties of an IP interface on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-setipinterfaceentry
func (row *MibIPInterfaceRow) Set() error {
	return setIPInterfaceEntry(row)
}

// get method returns all table rows as a Go slice.
func (tab *mibIPInterfaceTable) get() (s []MibIPInterfaceRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of network interfaces, addresses, and routes.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-freemibtable
func (tab *mibIPInterfaceTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

// Alias method returns a string that contains the alias name of the network interface.
func (row *MibIfRow2) Alias() string {
	return windows.UTF16ToString(row.alias[:])
}

// Description method returns a string that contains a description of the network interface.
func (row *MibIfRow2) Description() string {
	return windows.UTF16ToString(row.description[:])
}

// PhysicalAddress method returns the physical hardware address of the adapter for this network interface.
func (row *MibIfRow2) PhysicalAddress() []byte {
	return row.physicalAddress[:row.physicalAddressLength]
}

// PermanentPhysicalAddress method returns the permanent physical hardware address of the adapter for this network interface.
func (row *MibIfRow2) PermanentPhysicalAddress() []byte {
	return row.permanentPhysicalAddress[:row.physicalAddressLength]
}

// get method retrieves information for the specified interface on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getifentry2
func (row *MibIfRow2) get() (ret error) {
	return getIfEntry2(row)
}

// get method returns all table rows as a Go slice.
func (tab *mibIfTable2) get() (s []MibIfRow2) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of network interfaces, addresses, and routes.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-freemibtable
func (tab *mibIfTable2) free() {
	freeMibTable(unsafe.Pointer(tab))
}

// RawSockaddrInet union contains an IPv4, an IPv6 address, or an address family.
// https://docs.microsoft.com/en-us/windows/desktop/api/ws2ipdef/ns-ws2ipdef-_sockaddr_inet
type RawSockaddrInet struct {
	Family AddressFamily
	data   [26]byte
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&i))[:])
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// SetAddrPort method sets family, address, and port to the given IPv4 or IPv6 address and port.
// All other members of the structure are set to zero.
func (addr *RawSockaddrInet) SetAddrPort(addrPort netip.AddrPort) error {
	if addrPort.Addr().Is4() {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		addr4.Family = windows.AF_INET
		addr4.Addr = addrPort.Addr().As4()
		addr4.Port = htons(addrPort.Port())
		for i := range 8 {
			addr4.Zero[i] = 0
		}
		return nil
	} else if addrPort.Addr().Is6() {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		addr6.Family = windows.AF_INET6
		addr6.Addr = addrPort.Addr().As16()
		addr6.Port = htons(addrPort.Port())
		addr6.Flowinfo = 0
		scopeId := uint32(0)
		if z := addrPort.Addr().Zone(); z != "" {
			if s, err := strconv.ParseUint(z, 10, 32); err == nil {
				scopeId = uint32(s)
			}
		}
		addr6.Scope_id = scopeId
		return nil
	}
	return windows.ERROR_INVALID_PARAMETER
}

// SetAddr method sets family and address to the given IPv4 or IPv6 address.
// All other members of the structure are set to zero.
func (addr *RawSockaddrInet) SetAddr(netAddr netip.Addr) error {
	return addr.SetAddrPort(netip.AddrPortFrom(netAddr, 0))
}

// AddrPort returns the IP address and port.
func (addr *RawSockaddrInet) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr(), addr.Port())
}

// Addr returns IPv4 or IPv6 address, or an invalid address if the address is neither.
func (addr *RawSockaddrInet) Addr() netip.Addr {
	switch addr.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Addr)
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		a := netip.AddrFrom16(raw.Addr)
		if raw.Scope_id != 0 {
			a = a.WithZone(strconv.FormatUint(uint64(raw.Scope_id), 10))
		}
		return a
	}
	return netip.Addr{}
}

// Port returns the port if the address if IPv4 or IPv6, or 0 if neither.
func (addr *RawSockaddrInet) Port() uint16 {
	switch addr.Family {
	case windows.AF_INET:
		return ntohs((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Port)
	case windows.AF_INET6:
		return ntohs((*windows.RawSockaddrInet6)(unsafe.Pointer(addr)).Port)
	}
	return 0
}

// Init method initializes a MibUnicastIPAddressRow structure with default values for a unicast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-initializeunicastipaddressentry
func (row *MibUnicastIPAddressRow) Init() {
	initializeUnicastIPAddressEntry(row)
}

// get method retrieves information for an existing unicast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddressentry
func (row *MibUnicastIPAddressRow) get() error {
	return getUnicastIPAddressEntry(row)
}

// Set method sets the properties of an existing unicast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-setunicastipaddressentry
func (row *MibUnicastIPAddressRow) Set() error {
	return setUnicastIPAddressEntry(row)
}

// Create method adds a new unicast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry
func (row *MibUnicastIPAddressRow) Create() error {
	return createUnicastIPAddressEntry(row)
}

// Delete method deletes an existing unicast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry
func (row *MibUnicastIPAddressRow) Delete() error {
	return deleteUnicastIPAddressEntry(row)
}

// get method returns all table rows as a Go slice.
func (tab *mibUnicastIPAddressTable) get() (s []MibUnicastIPAddressRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of network interfaces, addresses, and routes.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-freemibtable
func (tab *mibUnicastIPAddressTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

// get method retrieves information for an existing anycast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getanycastipaddressentry
func (row *MibAnycastIPAddressRow) get() error {
	return getAnycastIPAddressEntry(row)
}

// Create method adds a new anycast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createanycastipaddressentry
func (row *MibAnycastIPAddressRow) Create() error {
	return createAnycastIPAddressEntry(row)
}

// Delete method deletes an existing anycast IP address entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteanycastipaddressentry
func (row *MibAnycastIPAddressRow) Delete() error {
	return deleteAnycastIPAddressEntry(row)
}

// get method returns all table rows as a Go slice.
func (tab *mibAnycastIPAddressTable) get() (s []MibAnycastIPAddressRow) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of network interfaces, addresses, and routes.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-freemibtable
func (tab *mibAnycastIPAddressTable) free() {
	freeMibTable(unsafe.Pointer(tab))
}

// IPAddressPrefix structure stores an IP address prefix.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_ip_address_prefix
type IPAddressPrefix struct {
	RawPrefix    RawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

// SetPrefix method sets IP address prefix using netip.Prefix.
func (prefix *IPAddressPrefix) SetPrefix(netPrefix netip.Prefix) error {
	err := prefix.RawPrefix.SetAddr(netPrefix.Addr())
	if err != nil {
		return err
	}
	prefix.PrefixLength = uint8(netPrefix.Bits())
	return nil
}

// Prefix returns IP address prefix as netip.Prefix.
func (prefix *IPAddressPrefix) Prefix() netip.Prefix {
	switch prefix.RawPrefix.Family {
	case windows.AF_INET:
		return netip.PrefixFrom(netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	case windows.AF_INET6:
		return netip.PrefixFrom(netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	}
	return netip.Prefix{}
}

// MibIPforwardRow2 structure stores information about an IP route entry.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_row2
type MibIPforwardRow2 struct {
	InterfaceLUID        LUID
	InterfaceIndex       uint32
	DestinationPrefix    IPAddressPrefix
	NextHop              RawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             RouteProtocol
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               RouteOrigin
}

// Init method initializes a MIB_IPFORWARD_ROW2 structure with default values for an IP route entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-initializeipforwardentry
func (row *MibIPforwardRow2) Init() {
	initializeIPForwardEntry(row)
}

// get method retrieves information for an IP route entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardentry2
func (row *MibIPforwardRow2) get() error {
	return getIPForwardEntry2(row)
}

// Set method sets the properties of an IP route entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-setipforwardentry2
func (row *MibIPforwardRow2) Set() error {
	return setIPForwardEntry2(row)
}

// Create method creates a new IP route entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2
func (row *MibIPforwardRow2) Create() error {
	return createIPForwardEntry2(row)
}

// Delete method deletes an IP route entry on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteipforwardentry2
func (row *MibIPforwardRow2) Delete() error {
	return deleteIPForwardEntry2(row)
}

// get method returns all table rows as a Go slice.
func (tab *mibIPforwardTable2) get() (s []MibIPforwardRow2) {
	return unsafe.Slice(&tab.table[0], tab.numEntries)
}

// free method frees the buffer allocated by the functions that return tables of network interfaces, addresses, and routes.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-freemibtable
func (tab *mibIPforwardTable2) free() {
	freeMibTable(unsafe.Pointer(tab))
}

//
// DNS API
//

// DnsInterfaceSettings is meant to be used with SetInterfaceDnsSettings
type DnsInterfaceSettings struct {
	Version             uint32
	_                   [4]byte
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

const (
	DnsInterfaceSettingsVersion1 = 1 // for DnsInterfaceSettings
	DnsInterfaceSettingsVersion2 = 2 // for DnsInterfaceSettingsEx
	DnsInterfaceSettingsVersion3 = 3 // for DnsInterfaceSettings3

	DnsInterfaceSettingsFlagIPv6                        = 0x0001
	DnsInterfaceSettingsFlagNameserver                  = 0x0002
	DnsInterfaceSettingsFlagSearchList                  = 0x0004
	DnsInterfaceSettingsFlagRegistrationEnabled         = 0x0008
	DnsInterfaceSettingsFlagRegisterAdapterName         = 0x0010
	DnsInterfaceSettingsFlagDomain                      = 0x0020
	DnsInterfaceSettingsFlagHostname                    = 0x0040
	DnsInterfaceSettingsFlagEnableLLMNR                 = 0x0080
	DnsInterfaceSettingsFlagQueryAdapterName            = 0x0100
	DnsInterfaceSettingsFlagProfileNameserver           = 0x0200
	DnsInterfaceSettingsFlagDisableUnconstrainedQueries = 0x0400 // v2 only
	DnsInterfaceSettingsFlagSupplementalSearchList      = 0x0800 // v2 only
	DnsInterfaceSettingsFlagDOH                         = 0x1000 // v3 only
	DnsInterfaceSettingsFlagDOHProfile                  = 0x2000 // v3 only
)
