// SPDX-License-Identifier: AGPL-3.0-or-later
#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/address_mapping.p4"

#if __TARGET_TOFINO__ == 1
    const PortId_t CPU_PORT = 64;
    const PortId_t RECIRCULATION_PORT = 68;
#elif __TARGET_TOFINO__ == 2
    const PortId_t CPU_PORT = 0;
    const PortId_t RECIRCULATION_PORT = 1;
#else
    #error
#endif

////////////////////////
// Ingress Processing //
////////////////////////

/** Headers **/

const int SC_MAX_INFO_CNT = 3;
const int SC_MAX_HF_CNT   = 63;
const int MAX_HF_PER_PASS = 12;

typedef bit<16> PathIndex_t;

const int CLASSIFIER_TABLE_SIZE = 8192;
const int UNREACHABLE_TABLE_SIZE = 8192;
const int PATH_TABLE_SIZE = 4096;
const int PATH_MTU_TABLE_SIZE = 1024;
const int PREFIX_MAP_SIZE = 4096;

const ResubmitType_t RESUBMIT_SCION = 1;
const DigestType_t DIGEST_GET_PATH = 1;

struct path_digest_t {
    map_isd_t isd;
    map_asn_t asn;
}

header resubmit_h {
    bit<8> discard_path;
}

// Internal header of packets that have been recirculated using the internal
// fixed recirculation ports. Packets are recirculated if we can't insert all
// hop fields in one pass.
header recirc_h {
    @padding bit<7> pad1;
    PortId_t        egress_port; // final egress port one all HFs have been inserted
    @padding bit<4> pad2;
    bit<4>          count;       // remaining passes
    PathIndex_t     path_index;  // selected path
}

struct scion_t {
    sc_common_h       common;
    sc_host_addr_4_h  dst_host_4;
    sc_host_addr_16_h dst_host_16;
    sc_host_addr_4_h  src_host_4;
    sc_host_addr_16_h src_host_16;
}

struct sc_path_t {
    sc_path_meta_h meta;
    sc_info_h      info0;
    sc_info_h      info1;
    sc_info_h      info2;
    sc_hop_blob_h  hop0;
    sc_hop_blob_h  hop1;
    sc_hop_blob_h  hop2;
    sc_hop_blob_h  hop3;
    sc_hop_blob_h  hop4;
    sc_hop_blob_h  hop5;
    sc_hop_blob_h  hop6;
    sc_hop_blob_h  hop7;
    sc_hop_blob_h  hop8;
    sc_hop_blob_h  hop9;
    sc_hop_blob_h  hop10;
    sc_hop_blob_h  hop11;
}

struct ingress_headers_t {
    recirc_h        recirc;
    ethernet_h      ether;
    // Underlay
    ipv4_h          ipv4;
    ipv6_h          ipv6;
    ipv6_opt_frag_h frag;
    icmp6_h         icmp;
    udp_h           outer_udp;
    // SCION
    scion_t         scion;
    sc_path_t       path;
    // Upper layer headers
    scmp_h          scmp;
    udp_h           udp;
    tcp_h           tcp;
    tcp_mss_h       tcp_mss;
}

/** Metadata **/

struct ingress_metadata_t {
    resubmit_h resubmit;
    sc_hop_h   last_hf;
    bit<8>     l4_type;
    bit<16>    l4_dst_port;

    bit<16>    l4_residual;       // original L4 checksum minus IP headers
    bit<16>    path_chksum;       // 1's complement sum of the SCION path
    bool       chksum_ipv4_scion; // compute UDP checksum for SCION over IPv4
    bool       chksum_ipv6_scion; // compute UDP checksum for SCION over IPv6
    bool       chksum_ipv6_udp;   // compute UDP/IPv6 checksum without SCION
    bool       chksum_ipv6_tcp;   // compute TCP/IPv6 checksum without SCION
}

/** Ingress Parser **/
#include "include/ingress_parser.p4"

/** Ingress Match-Action **/
#include "include/ingress_ip_to_scion.p4"
#include "include/ingress_scion_to_ip.p4"

control Ingress(
    inout ingress_headers_t                         hdr,
    inout ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    IpToScion() i2s;
    ScionToIp() s2i;

    // === Packet Ingress Table ===
    // Decide whether a packet contains a SCION header and what to do with it.
    // Drop the packet.
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
        exit;
    }

    // Resubmit and parse the full SCION header, discarding the hop fields in
    // the process.
    action discard_scion() {
        meta.resubmit.discard_path = 1;
        ig_dprsr_md.resubmit_type = RESUBMIT_SCION;
        exit;
    }

    action scion2ip() {
    }

    action ip2scion() {
    }

    table tab_ingress {
        key = {
            hdr.recirc.isValid()       : ternary;
            hdr.scion.common.isValid() : ternary;
            ig_intr_md.ingress_port    : ternary;
            hdr.udp.isValid()          : ternary;
            hdr.udp.dst                : ternary;
        }
        actions = {
            drop;
            discard_scion;
            ip2scion;
            scion2ip;
        }
        const default_action = drop();
        size = 512;
    }

    // === Apply ===

    apply {
        if (ig_prsr_md.parser_err != 0) {
            drop();
            exit;
        }

        switch (tab_ingress.apply().action_run) {
        ip2scion: {
            i2s.apply(hdr, meta, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);
        }
        scion2ip: {
            s2i.apply(hdr, meta, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);
        }}
    }
}

/** Ingress Deparser **/

control IgDeparser(packet_out                       pkt,
    inout ingress_headers_t                         hdr,
    in    ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Digest<path_digest_t>() path_digest;
    Resubmit() scion_resubmit;
    Checksum() ipv4_chksum;
    Checksum() udp_chksum;
    Checksum() tcp_chksum;

    apply {
        if (ig_dprsr_md.digest_type == DIGEST_GET_PATH) {
            path_digest.pack({extract_isd(hdr.ipv6.dst), extract_asn(hdr.ipv6.dst)});
        }
        if (ig_dprsr_md.resubmit_type == RESUBMIT_SCION) {
            scion_resubmit.emit<resubmit_h>(meta.resubmit);
        }
        if (hdr.ipv4.isValid()) { // compute IPv4 header checksum
            hdr.ipv4.chksum = ipv4_chksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src,
                hdr.ipv4.dst
            });
        }
        if (meta.chksum_ipv4_scion) { // compute outer checksum for SCION over IPv4
            hdr.outer_udp.chksum = udp_chksum.update({
                hdr.ipv4.src,
                hdr.ipv4.dst,
                8w0, hdr.ipv4.protocol,
                hdr.outer_udp.length,
                hdr.outer_udp.src,
                hdr.outer_udp.dst,
                hdr.scion.common,
                hdr.scion.dst_host_4,
                hdr.scion.dst_host_16,
                hdr.scion.src_host_4,
                hdr.scion.src_host_16,
                meta.path_chksum,
                meta.l4_residual
            });
        }
        if (meta.chksum_ipv6_scion) { // compute outer checksum for SCION over IPv6
            hdr.outer_udp.chksum = udp_chksum.update({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                8w0, hdr.ipv6.next_hdr,
                hdr.outer_udp.length,
                hdr.outer_udp.src,
                hdr.outer_udp.dst,
                hdr.scion.common,
                hdr.scion.dst_host_4,
                hdr.scion.dst_host_16,
                hdr.scion.src_host_4,
                hdr.scion.src_host_16,
                meta.path_chksum,
                meta.l4_residual
            });
        }
        if (meta.chksum_ipv6_udp) { // compute UDP checksum for packets translated from SCION to IPv6
            hdr.tcp.chksum = udp_chksum.update({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                8w0, hdr.ipv6.next_hdr,
                hdr.udp.length,
                hdr.udp.src,
                hdr.udp.dst,
                meta.l4_residual
            });
        }
        if (meta.chksum_ipv6_tcp) { // compute TCP checksum for packets translated from SCION to IPv6
            hdr.tcp.chksum = tcp_chksum.update({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                hdr.ipv6.payload_len,
                8w0, hdr.ipv6.next_hdr,
                hdr.tcp,
                hdr.tcp_mss,
                meta.l4_residual
            });
        }
        pkt.emit(hdr);
    }
}

///////////////////////
// Egress Processing //
///////////////////////

/** Headers **/

struct egress_headers_t {
}

/** Metadata **/

struct egress_metadata_t {
}

/** Egress Parser **/

parser EgParser(packet_in           pkt,
    out egress_headers_t            hdr,
    out egress_metadata_t           meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/** Egress Match-Action **/

control Egress(
    inout egress_headers_t                            hdr,
    inout egress_metadata_t                           meta,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply {
    }
}

/** Egress Deparser **/

control EgDeparser(packet_out                      pkt,
    inout egress_headers_t                         hdr,
    in    egress_metadata_t                        meta,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

//////////////
// Pipeline //
//////////////

Pipeline(
    IgParser(),
    Ingress(),
    IgDeparser(),
    EgParser(),
    Egress(),
    EgDeparser()
) scitra;

Switch(scitra) main;
