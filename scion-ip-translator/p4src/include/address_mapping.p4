// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _SCITRA_ADDR_MAPPING_GUARD
#define _SCITRA_ADDR_MAPPING_GUARD

#include <core.p4>
#include <tna.p4>

const int MAPPED_ISD_BITS = 12;
const int MAPPED_AS_BITS = 20;
const bit<8> SCION_PREFIX = 0xfc;

typedef bit<(MAPPED_ISD_BITS)> map_isd_t;
typedef bit<(MAPPED_AS_BITS)> map_asn_t;

#define extract_prefix(ip) ip[127:120]
#define extract_isd(ip) ip[119:108]
#define extract_asn(ip) ip[107:88]
#define extract_network(ip) ip[87:64]
#define extract_host_v4(ip) ip[31:0]
#define extract_host_v6(ip) ip[63:0]

void decode_isd(out sc_isd_t isd, in bit<128> ip) {
    isd = (sc_isd_t)(ip[118:107]);
}

void decode_asn(inout sc_asn_t asn, in bit<128> ip) {
    if (ip[106:106] == 0) {
        // BGP ASN
        @in_hash {
            asn[47:32] = 0;
            asn[31:0] = (bit<32>)(ip[106:88]);
        }
    } else {
        // Public SCION ASN
        @in_hash {
            asn[47:32] = 2;
            asn[31:0] = (bit<32>)(ip[106:88]);
        }
    }
}

#endif // _SCITRA_ADDR_MAPPING_GUARD
