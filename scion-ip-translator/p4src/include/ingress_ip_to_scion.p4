// SPDX-License-Identifier: AGPL-3.0-or-later

#define tab_path_meta() \
    action set_path_meta(bit<2> curr_inf, bit<6> curr_hf, bit<6> seg0, bit<6> seg1, bit<6> seg2) { \
        hdr.path.meta.curr_inf = curr_inf; \
        hdr.path.meta.curr_hf = curr_hf; \
        hdr.path.meta.rsv = 0; \
        hdr.path.meta.seg0_len = seg0; \
        hdr.path.meta.seg1_len = seg1; \
        hdr.path.meta.seg2_len = seg2; \
        hdr.path.meta.setValid(); \
    } \
    table tab_path_meta { \
        key = { \
            path_index : exact; \
        } \
        actions = { \
            set_path_meta; \
        } \
        size = PATH_TABLE_SIZE; \
    }

#define DECLARE_PATH_META_TABLES \
    tab_path_meta()

#define INSERT_PATH_META() \
    tab_path_meta.apply();

#define tab_inf(index) \
    action set_inf_ ## index(bit<64> inf) { \
        hdr.path.info ## index.rsv1    = inf[63:58]; \
        hdr.path.info ## index.peering = inf[57:57]; \
        hdr.path.info ## index.cons    = inf[56:56]; \
        hdr.path.info ## index.rsv2    = inf[55:48]; \
        hdr.path.info ## index.seg_id  = inf[47:32]; \
        hdr.path.info ## index.tstamp  = inf[31:0]; \
        hdr.path.info ## index.setValid(); \
    } \
    table tab_inf_ ## index { \
        key = { \
            path_index : exact; \
        } \
        actions = { \
            NoAction; \
            set_inf_ ## index; \
        } \
        const default_action = NoAction(); \
        size = PATH_TABLE_SIZE; \
    }

#define DECLARE_INF_TABLES \
    tab_inf(0) \
    tab_inf(1) \
    tab_inf(2)

#define INSERT_INF_FIELDS() \
    tab_inf_0.apply(); \
    tab_inf_1.apply(); \
    tab_inf_2.apply()

#define tab_hf(index) \
    action set_hop_ ## index(bit<96> hf) { \
        hdr.path.hop ## index.data = hf; \
        hdr.path.hop ## index.setValid(); \
    } \
    table tab_hf_ ## index { \
        key = { \
            recirc_count : exact; \
            path_index   : exact; \
        } \
        actions = { \
            NoAction; \
            set_hop_ ## index; \
        } \
        const default_action = NoAction(); \
        size = PATH_TABLE_SIZE; \
    }

#define DECLARE_HF_TABLES \
    tab_hf(0) \
    tab_hf(1) \
    tab_hf(2) \
    tab_hf(3) \
    tab_hf(4) \
    tab_hf(5) \
    tab_hf(6) \
    tab_hf(7) \
    tab_hf(8) \
    tab_hf(9) \
    tab_hf(10) \
    tab_hf(11)

#define INSERT_HOP_FIELDS() \
    tab_hf_0.apply(); \
    tab_hf_1.apply(); \
    tab_hf_2.apply(); \
    tab_hf_3.apply(); \
    tab_hf_4.apply(); \
    tab_hf_5.apply(); \
    tab_hf_6.apply(); \
    tab_hf_7.apply(); \
    tab_hf_8.apply(); \
    tab_hf_9.apply(); \
    tab_hf_10.apply(); \
    tab_hf_11.apply();

// IP to SCION Translation
control IpToScion(
    inout ingress_headers_t                         hdr,
    inout ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    bit<6> dscp = 0;          // DS code point from IPv4/6 header
    bit<8> traffic_class = 0; // traffic class for path lookup

    PathIndex_t path_index = 0; // index of the selected path, empty path is 0
    bit<4> recirc_count = 0;    // number of recirculations still required
    bit<9> next_hop_br = 0;     // next hop border router for outgoing packets
    bit<8> path_len = 0;        // path length in units of 4 bytes
    bit<16> tcp_mss = 0;        // MSS for TCP (path_mtu - 20 bytes)

    // === Global Actions ===

    // Drop the packet.
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    // === Recirculation Table ===
    // Set the egress port to a recirculation port determined by the control
    // plane.

    action recirculate(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table tab_recirc {
        key = {
            ig_intr_md.ingress_port[8:7] : exact; // Pipe ID
        }
        actions = {
            recirculate;
        }
        const default_action = recirculate(RECIRCULATION_PORT);
        size = 4;
    }

    // === Path Insertion Tables ===
    // Tables keyed on path_index and recirc_count that contain the SCION path
    // to be inserted-

    DECLARE_PATH_META_TABLES
    DECLARE_INF_TABLES
    DECLARE_HF_TABLES

    // === Traffic Classifier ===
    // Classifies packets for path selection.

    action set_traffic_class(bit<8> tc) {
        traffic_class = tc;
    }

    table tab_classifier {
        key = {
            dscp             : ternary;
            meta.l4_type     : ternary;
            meta.l4_dst_port : ternary;
        }
        actions = {
            set_traffic_class;
        }
        default_action = set_traffic_class(0);
        size = CLASSIFIER_TABLE_SIZE;
    }

    // === Destination Host Decoder ===
    // Writes the IPv4 or IPv6 destination host address extracted from a
    // SCION-mapped IP address to the SCION header. If this tables misses, the
    // destination was not a SCION-mapped IP address. This table has only
    // constant entires.

    action set_scion_dst_v4() {
        hdr.scion.dst_host_4.addr = extract_host_v4(hdr.ipv6.dst);
        hdr.scion.dst_host_4.setValid();
        hdr.scion.common.hdr_len = hdr.scion.common.hdr_len + 1;
        hdr.scion.common.host_type_len = 0x00;
    }

    action set_scion_dst_v6() {
        hdr.scion.dst_host_16.addr = hdr.ipv6.dst;
        hdr.scion.dst_host_16.setValid();
        hdr.scion.common.hdr_len = hdr.scion.common.hdr_len + 4;
        hdr.scion.common.host_type_len = 0x30;
    }

    @hidden
    table tab_dst_host {
        key = {
            hdr.ipv6.dst : ternary;
        }
        actions = {
            drop;
            set_scion_dst_v4;
            set_scion_dst_v6;
        }
        const default_action = drop();
        const entries = {
            (0xfc00_0000_0000_0000_0000_ffff_0000_0000 &&&
             0xfe00_0000_00ff_ffff_ffff_ffff_0000_0000): set_scion_dst_v4;
            (0xfc00_0000_0000_0000_0000_0000_0000_0000 &&&
             0xfe00_0000_0000_0000_0000_0000_0000_0000): set_scion_dst_v6;
        }
        size = 2;
    }

    // === Source IA Table ===
    // Sets the source ISD and ASN in the SCION header to a value provided by
    // the control plane. The table is matching on nothing and only the default
    // action is used.

    action set_source_ia(sc_isd_t isd, sc_asn_t asn, bit<20> encoded_asn) {
        hdr.scion.common.src_isd = isd;
        hdr.scion.common.src_asn = asn;
        extract_isd(hdr.scion.src_host_16.addr) = (bit<12>)(isd);
        extract_asn(hdr.scion.src_host_16.addr) = encoded_asn;
    }

    table tab_source_ia {
        actions = {
            set_source_ia;
        }
        default_action = set_source_ia(0, 0, 0);
        size = 1; // doesn't compile with size 0
    }

    // === Source Subnet Mapping ===
    // Encode the subnet of the packet source in the network part of the
    // SCION-mapped source host address we include in the SCION address header.

    action set_scion_src_subnet(bit<24> subnet) {
        extract_network(hdr.scion.src_host_16.addr) = subnet;
    }

    table tab_src_network_map {
        key = {
            hdr.ipv6.src[127:64] : lpm;
        }
        actions = {
            set_scion_src_subnet;
        }
        size = PREFIX_MAP_SIZE;
    }

    // === Unreachable ASes Table ===
    // Cache of ASes that we attempted to contact, but do not have a path to.
    // To avoid repeated path lookups, assume the AS remains unreachable while
    // it is in this table.

    // Reply with ICMP destination unreachable.
    action icmp_unreachable() {
        hdr.icmp.setValid();
        hdr.icmp.type = icmp6_type.DestUnreach;
        hdr.icmp.code = 0;   // no route to destination
        hdr.icmp.param1 = 0; // unused
        hdr.icmp.param2 = 0; // unused
        // TODO: Send to CPU or mirror to CPU and drop or return to sender directly
    }

    table tab_unreachable {
        key = {
            extract_isd(hdr.ipv6.dst) : exact;
            extract_asn(hdr.ipv6.dst) : exact;
        }
        actions = {
            icmp_unreachable;
            NoAction;
        }
        const default_action = NoAction();
        size = UNREACHABLE_TABLE_SIZE;
    }

    // === Path Lookup Table ===
    // Contains metadata on all paths installed in the data plane. The actual
    // path is stored in the info and hop field tables indexed by the ID
    // returned from this table.

    action set_path(PathIndex_t path, bit<4> recirc, bit<9> br, bit<16> chksum, bit<8> length, bit<16> mss) {
        hdr.scion.common.path_type = sc_path_type.SCION;
        path_index = path;
        recirc_count = recirc;
        next_hop_br = br;
        meta.path_chksum = chksum;
        path_len = length;
        tcp_mss = mss;
    }

    action set_empty_path(bit<16> mss) {
        hdr.scion.common.path_type = sc_path_type.EMPTY;
        path_index = 0;
        recirc_count = 0;
        next_hop_br = 0;
        meta.path_chksum = 0;
        path_len = 0;
        tcp_mss = mss;
    }

    @idletime_precision(3)
    table tab_path {
        key = {
            extract_isd(hdr.ipv6.dst) : exact;
            extract_asn(hdr.ipv6.dst) : exact;
            traffic_class             : ternary;
        }
        actions = {
            set_path;
            set_empty_path;
        }
        size = PATH_TABLE_SIZE;
        idle_timeout = true;
    }

    // === Next Hop Table ===
    // Addresses of neighboring SCION routers we can send packets to.
    // If SciTra is configured as a BR, links to other routers can use either
    // IPv4 or IPv6. If there is an external BR, the link has to be IPv6.

    action forward_to_br_v4(PortId_t egr_port, mac_addr_t mac, bit<32> ip, bit<16> port) {
        ig_tm_md.ucast_egress_port = egr_port;
        hdr.ether.dst = mac;
        hdr.ipv4.dst = ip;
        hdr.outer_udp.dst = port;
        hdr.ipv4.setValid();
        hdr.ipv6.setInvalid();
        hdr.outer_udp.setValid();
        meta.chksum_ipv4_scion = true;
    }

    action forward_to_br_v6(PortId_t egr_port, mac_addr_t mac, bit<128> ip, bit<16> port) {
        ig_tm_md.ucast_egress_port = egr_port;
        hdr.ether.dst = mac;
        hdr.ipv6.dst = ip;
        hdr.outer_udp.dst = port;
        hdr.ipv4.setInvalid();
        hdr.ipv6.setValid();
        hdr.outer_udp.setValid();
        meta.chksum_ipv6_scion = true;
    }

    table tab_next_hop {
        key = {
            next_hop_br : exact;
        }
        actions = {
            forward_to_br_v4;
            forward_to_br_v6;
        }
        size = 512;
    }

    // === Underlay Source Address Table ===
    // Sets the underlay source address of packets sent to other BRs.
    // If the SciTra is not working as a BR, this table must be empty.

    action set_underlay_source_v4(mac_addr_t mac, bit<32> ip, bit<16> port) {
        hdr.ether.src = mac;
        hdr.ipv4.src = ip;
        hdr.outer_udp.src = port;
    }

    action set_underlay_source_v6(mac_addr_t mac, bit<128> ip, bit<16> port) {
        hdr.ether.src = mac;
        hdr.ipv6.src = ip;
        hdr.outer_udp.src = port;
    }

    table tab_underlay_source {
        key = {
            ig_tm_md.ucast_egress_port : exact;
        }
        actions = {
            NoAction;
            set_underlay_source_v4;
            set_underlay_source_v6;
        }
        const default_action = NoAction();
        size = 512;
    }

    // == Path MTU Check ===
    // This table matches the required payload capacity against the available
    // MTU on different paths. Since the table used ternary matchers, the
    // control plane can group paths with the same MTU together to save space.

    action icmp_too_big(bit<16> mtu) {
        hdr.icmp.setValid();
        hdr.icmp.type = icmp6_type.PacketTooBig;
        hdr.icmp.code = 0;   // unused
        hdr.icmp.param1 = 0; // MTU upper part
        hdr.icmp.param2 = mtu;
        // TODO: Send to CPU or mirror to CPU and drop or return to sender directly
    }

    table tab_path_mtu {
        key = {
            path_index           : ternary;
            hdr.ipv6.payload_len : range;
        }
        actions = {
            NoAction;
            icmp_too_big;
        }
        const default_action = NoAction();
        size = PATH_MTU_TABLE_SIZE;
    }

    // === TCP MSS Clamping ===
    // This table clamps the MSS of TCP connections to fit the selected path.
    // If the packet is not a TCP SYN, no action is taken.

    action clamp_mss() {
        hdr.tcp_mss.mss = min(hdr.tcp_mss.mss, tcp_mss);
    }

    @hidden
    table tab_tcp_mss_clamp {
        key = {
            hdr.tcp.syn      : exact;
            hdr.tcp_mss.type : exact;
        }
        actions = {
            NoAction;
            clamp_mss;
        }
        const default_action = NoAction;
        const entries = {
            (1, tcp_opt_type.MSS): clamp_mss;
        }
        size = 1;
    }

    // === Apply ===
    // Translate IP to SCION packets.

    apply {
        // Classify packet
        if (hdr.ipv4.isValid()) {
            dscp = hdr.ipv4.diffserv[7:2];
            tab_classifier.apply();
        } else if (hdr.ipv6.isValid()) {
            dscp = hdr.ipv6.traffic_class[7:2];
            tab_classifier.apply();
        }

        if (hdr.recirc.isValid()) { // Path taken by recirculated packets

            hdr.recirc.count = hdr.recirc.count |-| 1;
            if (hdr.recirc.count == 0) {
                // Stop recirculating
                ig_tm_md.ucast_egress_port = hdr.recirc.egress_port;
                hdr.recirc.setInvalid();
            }
            path_index = hdr.recirc.path_index;
            recirc_count = hdr.recirc.count;

        } else if (hdr.ipv6.isValid()) { // Path taken by regular packets

            // Initialize SCION common header
            hdr.scion.common.version = 0;
            hdr.scion.common.qos = 0;
            hdr.scion.common.flow_id = hdr.ipv6.flow_label;
            hdr.scion.common.next_hdr = hdr.ipv6.next_hdr; // TODO: ICMP->SCMP translation
            hdr.scion.common.hdr_len = (SC_COMMON_HDR_BYTES + 16) / 4;
            hdr.scion.common.payload_len = hdr.ipv6.payload_len;

            // Set source addresses in SCION header
            tab_source_ia.apply();
            tab_src_network_map.apply();
            extract_prefix(hdr.scion.src_host_16.addr) = SCION_PREFIX;
            extract_host_v6(hdr.scion.src_host_16.addr) = hdr.ipv6.src[63:0];
            if (extract_prefix(hdr.ipv6.src) == SCION_PREFIX) {
                hdr.scion.src_host_16.addr = hdr.ipv6.src;
            }

            if (tab_dst_host.apply().hit) {
                if (tab_unreachable.apply().miss) {
                    if (tab_path.apply().miss) {
                        // Send digest and drop
                        ig_dprsr_md.digest_type = DIGEST_GET_PATH;
                        drop();
                    } else {
                        switch (tab_path_mtu.apply().action_run) {
                        icmp_too_big: {
                            hdr.scion.dst_host_4.setInvalid();
                            hdr.scion.dst_host_16.setInvalid();
                        }
                        NoAction: {
                            hdr.scion.common.hdr_len = hdr.scion.common.hdr_len + path_len;

                            if (hdr.scion.common.path_type == sc_path_type.EMPTY) {
                                // TODO: AS-internal IP->SCION translation
                            } else {
                                // Set underlay destination and source
                                tab_next_hop.apply();
                                tab_underlay_source.apply();
                            }

                            // Set SCION destination AS
                            decode_isd(hdr.scion.common.dst_isd, hdr.ipv6.dst);
                            decode_asn(hdr.scion.common.dst_asn, hdr.ipv6.dst);

                            // Clamp TCP MSS in SYN packets
                            if (hdr.tcp_mss.isValid()) {
                                tab_tcp_mss_clamp.apply();
                            }

                            // Insert path
                            hdr.scion.common.setValid();
                            hdr.scion.src_host_16.setValid();
                            INSERT_PATH_META();
                            INSERT_INF_FIELDS();

                            // Recirculate if the path is too long
                            if (recirc_count != 0) {
                                hdr.recirc.setValid();
                                hdr.recirc.count = recirc_count;
                                hdr.recirc.path_index = path_index;
                                hdr.recirc.egress_port = ig_tm_md.ucast_egress_port;
                            }
                        }}
                    }
                }
            }
        }

        // Invoke these tables last to ensure a consistent table order between
        // the regular and recirculation branch.
        INSERT_HOP_FIELDS();
        if (recirc_count != 0) tab_recirc.apply();
    }
}
