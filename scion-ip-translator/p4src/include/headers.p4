// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _SCITRA_HEADERS_GUARD
#define _SCITRA_HEADERS_GUARD

#include <core.p4>
#include <tna.p4>

//////////////////////
// Standard Headers //
//////////////////////

type bit<48> mac_addr_t;

enum bit<16> ether_type {
    IPV4 = 0x0800,
    ARP  = 0x0806,
    IPV6 = 0x86DD,
}

enum bit<8> ip_proto_t {
    ICMP        = 1,
    TCP         = 6,
    UDP         = 17,
    IPv6Frag    = 44,
    ICMPv6      = 58,
    HopByHopExt = 200, // SCION
    End2EndExt  = 201, // SCION
    SCMP        = 202, // SCION
    BFD         = 203, // SCION
}

enum bit<8> icmp6_type {
    DestUnreach   = 1,
    PacketTooBig  = 2,
    TimeExceeded  = 3,
    ParamProblem  = 4,
    EchoRequest   = 128,
    EchoReply     = 129,
    RouterSolicit = 133,
    RouterAdvert  = 134,
    NeighSolicit  = 135,
    NeighAdvert   = 136,
    Redirect      = 137,
}

enum bit<8> tcp_opt_type {
    EOL = 0,
    NOP = 1,
    MSS = 2,
}

header ethernet_h {
    mac_addr_t dst;
    mac_addr_t src;
    ether_type etype;
}

header ipv4_h {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    total_len;
    bit<16>    id;
    bit<3>     flags;
    bit<13>    frag_offset;
    bit<8>     ttl;
    ip_proto_t protocol;
    bit<16>    chksum;
    bit<32>    src;
    bit<32>    dst;
}

header ipv6_h {
    bit<4>     version;
    bit<8>     traffic_class;
    bit<20>    flow_label;
    bit<16>    payload_len;
    ip_proto_t next_hdr;
    bit<8>     hop_limit;
    bit<128>   src;
    bit<128>   dst;
}

header ipv6_opt_frag_h {
    ip_proto_t next_hdr;
    bit<8>     rsv1;
    bit<13>    frag_offset;
    bit<2>     rsv2;
    bit<1>     more_fragments;
}

header icmp6_h {
    icmp6_type type;
    bit<8>     code;
    bit<16>    chksum;
    bit<16>    param1;
    bit<16>    param2;
}

header udp_h {
    bit<16> src;
    bit<16> dst;
    bit<16> length;
    bit<16> chksum;
}

header tcp_h {
    bit<16> src;
    bit<16> dst;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<4>  reserved;
    bit<6>  flags;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> wnd;
    bit<16> chksum;
    bit<16> urgent;
}

header tcp_mss_h {
    tcp_opt_type type;   // must be MSS
    bit<8>       length; // must be 4
    bit<16>      mss;
}

///////////////////
// SCION Headers //
///////////////////

enum bit<8> sc_path_type {
    EMPTY   = 0,
    SCION   = 1,
    ONE_HOP = 2,
    EPIC    = 3,
    COLIBRI = 4
}

enum bit<8> scmp_type {
    DestUnreach   = 1,
    PacketTooBig  = 2,
    ParamProblem  = 4,
    ExtIfaceDown  = 5,
    IntConnDown   = 6,
    EchoRequest   = 128,
    EchoReply     = 129,
    TraceRequest  = 130,
    TraceReply    = 131,
}

typedef bit<16> sc_isd_t;
typedef bit<48> sc_asn_t;

const int SC_MAX_HDR_BYTES    = 1020; // 255 * 4 bytes
const int SC_COMMON_HDR_BYTES = 28;   // 7 * 4 bytes

header sc_common_h {
    // Common SCION header
    bit<4>       version;       // header version (= 0)
    bit<8>       qos;           // traffic class
    bit<20>      flow_id;       // mandatory flow id
    ip_proto_t   next_hdr;      // next header type
    bit<8>       hdr_len;       // header length in units of 4 bytes
    bit<16>      payload_len;   // payload length in bytes
    sc_path_type path_type;     // path type
    bit<8>       host_type_len; // DT, DL, ST, SL
    bit<16>      rsv;           // reserved

    // Common address header
    sc_isd_t dst_isd;
    sc_asn_t dst_asn;
    sc_isd_t src_isd;
    sc_asn_t src_asn;
}

// 4 byte host address
header sc_host_addr_4_h {
    bit<32> addr;
}

// 16 byte host address
header sc_host_addr_16_h {
    bit<128> addr;
}

header scmp_h {
    scmp_type type;
    bit<8>    code;
    bit<16>   chksum;
    bit<16>   param1;
    bit<16>   param2;
}

/////////////////////////
// Standard SCION Path //
/////////////////////////

const int SC_PATH_META_BYTES  = 4;  // 1 * 4 byte
const int SC_INFO_FIELD_BYTES = 8;  // 2 * 4 byte
const int SC_HOP_FIELD_BYTES  = 12; // 3 * 4 byte

// SCION Path meta header
header sc_path_meta_h {
    bit<2> curr_inf; // index of the current info field
    bit<6> curr_hf;  // index of the current hop field
    bit<6> rsv;      // reserved
    bit<6> seg0_len; // number of hop fields in path segment 0
    bit<6> seg1_len; // number of hop fields in path segment 1
    bit<6> seg2_len; // number of hop fields in path segment 2
}

// Info field
header sc_info_h {
    bit<6>  rsv1;    // reserved
    bit<1>  peering; // peering hop
    bit<1>  cons;    // path in construction direction (1) or against construction direction (0)
    bit<8>  rsv2;    // reserved
    bit<16> seg_id;  // segment ID for MAC chaining
    bit<32> tstamp;  // timestamp
}

header sc_info_blob_h {
    bit<64> data;
}

// Hop field
header sc_hop_h {
    bit<6>  rsv;      // reserved
    bit<1>  ig_alert; // ingress router alert
    bit<1>  eg_alert; // egress router alert
    bit<8>  exp_time; // expiration time
    bit<16> ig_if;    // AS ingress IFID
    bit<16> eg_if;    // AS egress IFID
    bit<48> mac;      // message authentication code
}

header sc_hop_blob_h {
    bit<96> data;
}

#endif // _SCITRA_HEADERS_GUARD
