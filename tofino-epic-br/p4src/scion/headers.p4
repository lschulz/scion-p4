// SPDX-License-Identifier: BSD-3-Clause AND AGPL-3.0-or-later

/* 
 * Copyright (c) 2021, SIDN Labs
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __SCION_P4__
#define __SCION_P4__


/*************************************************************************
*********************** C O N S T A N T S  *******************************
*************************************************************************/

#define MAX_SCION_HF_CNT 8
#define MAX_SCION_HDR_LEN 1020
#define SCION_COMMON_HDR_LEN 12
#define SCION_ADDR_COMMON_HDR_LEN 16
#define SCION_PATH_META_LEN 4
#define SCION_INFO_LEN 6
#define SCION_HOP_LEN 12


/*************************************************************************
************************* H E A D E R S  *********************************
*************************************************************************/

typedef bit<16> isdAddr_t;
typedef bit<48> asAddr_t;

enum bit<8> PathType {
  EMPTY = 0x00,
  SCION = 0x01,
  ONEHOP = 0x02,
  EPIC = 0x03
}

header scion_common_t {
    bit<4>    version;
    bit<8>    qos;
    bit<20>   flowID;
    bit<8>    nextHdr;
    bit<8>    hdrLen;
    bit<16>   payloadLen;
    PathType  pathType;
    bit<2>    dt;
    bit<2>    dl;//4,8,12,16
    bit<2>    st;
    bit<2>    sl;//4,8,12,16
    bit<16>   rsv;
}

header scion_addr_common_t {
    isdAddr_t dstISD;
    asAddr_t  dstAS;
    isdAddr_t srcISD;
    asAddr_t  srcAS;
}


header scion_addr_host_32_t {
    bit<32> host;
}

header scion_addr_host_64_t {
    bit<64> host;
}

header scion_addr_host_96_t {
    bit<96> host;
}

header scion_addr_host_128_t {
    bit<128> host;
}

header scion_path_meta_t {
    bit<2>    currInf;
    bit<6>    currHF;
    bit<6>    rsv;
    bit<6>    seg0Len;
    bit<6>    seg1Len;
    bit<6>    seg2Len;
}

header scion_path_epic_t {
    bit<32> timestamp;
    bit<32> counter;
    bit<32> phvf;
    bit<32> lhvf;
}

header scion_info_field_t {
    bit<6>    rsv0;
    bit<1>    peering;
    bit<1>    direction;
    bit<8>    rsv1;
    bit<16>   segId;
    bit<32>   timestamp;
}

header scion_hop_field_t {
    bit<8>    routerAlerts;
    bit<8>    expTime;
    bit<16>   inIf;
    bit<16>   egIf;
    bit<48>   mac;
}

header scion_hop_by_hop_opt_t {
    bit<8> nextHdr;
    bit<8> extLen;
    bit<8> optType;
    bit<8> optDataLen;
}
#endif //__SCION_P4__
