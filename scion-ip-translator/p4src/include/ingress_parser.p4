// SPDX-License-Identifier: AGPL-3.0-or-later

parser IgParser(packet_in            pkt,
    out ingress_headers_t            hdr,
    out ingress_metadata_t           meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    // Checksum that is written to the inner L4 haeder when encapsulating in
    // SCION. When the packet is decapsulated by a translator, the new IP header
    // is added to the checksum again. If a native SCION host is receiving a
    // translated packet, the checksum is going to be incorrect, however no
    // other SCION implementation computes the inner checksum anyway.
    Checksum() l4_chksum;

    // Set of recirculations ports used for inserting long paths.
    value_set<bit<PORT_ID_WIDTH>>(8) recirc_ports;

    // The parser counter is used to keep track of the remaining SCION header
    // length. By subtracting all header we have parsed, it can tell us the the
    // number of hop fields in the path.
    ParserCounter() counter;

    state start {
        meta = {
            {0},
            {0, 0, 0, 0, 0, 0, 0},
            0, 0,
            0, 0, false, false, false, false
        };
        pkt.extract(ig_intr_md);
        transition select (ig_intr_md.resubmit_flag) {
            0: regular;
            1: resubmitted;
        }
    }

    state regular {
        pkt.advance(PORT_METADATA_SIZE);
        transition select (ig_intr_md.ingress_port) {
            recirc_ports: recirc;
            default     : ethernet;
        }
    }

    state recirc {
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.recirc);
        transition ethernet_scion;
    }

    state resubmitted {
        meta.resubmit = pkt.lookahead<resubmit_h>();
        pkt.advance(PORT_METADATA_SIZE);
        transition select (meta.resubmit.discard_path) {
            0      : ethernet_scion;
            default: ethernet_scion_discard;
        }
    }

    state ethernet {
        pkt.extract(hdr.ether);
        transition select (hdr.ether.etype) {
            ether_type.IPV4: ipv4;
            ether_type.IPV6: ipv6;
            default        : accept;
        }
    }

    state ethernet_scion {
        pkt.extract(hdr.ether);
        transition select (hdr.ether.etype) {
            ether_type.IPV4: ipv4_scion;
            ether_type.IPV6: ipv6_scion;
        }
    }

    state ethernet_scion_discard {
        pkt.extract(hdr.ether);
        transition select (hdr.ether.etype) {
            ether_type.IPV4: ipv4_scion_discard;
            ether_type.IPV6: ipv6_scion_discard;
        }
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);
        meta.l4_type = hdr.ipv4.protocol;

        // don't parse fragments or IPv4 options
        transition select (hdr.ipv4.frag_offset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (0, 5, ip_proto_t.ICMP): accept;
            (0, 5, ip_proto_t.TCP ): tcp;
            (0, 5, ip_proto_t.UDP ): udp;
            default                : reject;
        }
    }

    state ipv4_scion {
        pkt.extract(hdr.ipv4);
        meta.l4_type = hdr.ipv4.protocol;
        transition udp_scion;
    }

    state ipv4_scion_discard {
        pkt.extract(hdr.ipv4);
        meta.l4_type = hdr.ipv4.protocol;
        transition udp_scion_discard;
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);
        meta.l4_type = hdr.ipv6.next_hdr;

        l4_chksum.subtract({
            hdr.ipv6.src,
            hdr.ipv6.dst,
            24w0, hdr.ipv6.next_hdr
        });

        transition select (hdr.ipv6.next_hdr) {
            ip_proto_t.ICMPv6: icmp6;
            ip_proto_t.TCP   : tcp;
            ip_proto_t.UDP   : udp;
            default          : reject;
        }
    }

    state ipv6_scion {
        pkt.extract(hdr.ipv6);
        meta.l4_type = hdr.ipv6.next_hdr;

        l4_chksum.subtract({
            hdr.ipv6.src,
            hdr.ipv6.dst,
            24w0, hdr.ipv6.next_hdr
        });

        transition udp_scion;
    }

    state ipv6_scion_discard {
        pkt.extract(hdr.ipv6);
        meta.l4_type = hdr.ipv6.next_hdr;

        l4_chksum.subtract({
            hdr.ipv6.src,
            hdr.ipv6.dst,
            24w0, hdr.ipv6.next_hdr
        });

        transition udp_scion_discard;
    }

    // TODO: Can merge with scmp?
    state icmp6 {
        pkt.extract(hdr.icmp);
        meta.l4_dst_port = 0;
        // TODO: Checksum?
        transition accept;
    }

    state tcp {
        pkt.extract(hdr.tcp);
        meta.l4_dst_port = hdr.tcp.dst;
        l4_chksum.subtract(hdr.tcp);
        l4_chksum.subtract_all_and_deposit(meta.l4_residual);
        transition select (hdr.tcp.data_offset) {
            5: accept; // no options
            _: tcp_opt;
        }
    }

    state tcp_opt {
        // Extract the first option, check type in ingress control
        pkt.extract(hdr.tcp_mss);
        transition accept;
    }

    state udp {
        pkt.extract(hdr.udp);
        meta.l4_dst_port = hdr.udp.dst;

        l4_chksum.subtract(hdr.udp.chksum);
        l4_chksum.subtract_all_and_deposit(meta.l4_residual);

        transition accept;
    }

    state udp_scion {
        pkt.extract(hdr.outer_udp);
        transition scion;
    }

    state udp_scion_discard {
        pkt.extract(hdr.outer_udp);
        transition scion_discard;
    }

    ///////////
    // SCION //
    ///////////

    state scion {
        pkt.extract(hdr.scion.common);
        counter.set(hdr.scion.common.hdr_len);
        counter.decrement(SC_COMMON_HDR_BYTES / 4);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0xf0: dst_host_4;
            0x30 &&& 0xf0: dst_host_16;
        }
    }

    state scion_discard {
        pkt.extract(hdr.scion.common);
        counter.set(hdr.scion.common.hdr_len);
        counter.decrement(SC_COMMON_HDR_BYTES / 4);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0xf0: dst_host_4_discard;
            0x30 &&& 0xf0: dst_host_16_discard;
        }
    }

    state dst_host_4 {
        pkt.extract(hdr.scion.dst_host_4);
        counter.decrement(1);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0x0f: src_host_4;
            0x03 &&& 0x0f: src_host_16;
        }
    }

    state dst_host_4_discard {
        pkt.extract(hdr.scion.dst_host_4);
        counter.decrement(1);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0x0f: src_host_4_discard;
            0x03 &&& 0x0f: src_host_16_discard;
        }
    }

    state dst_host_16 {
        pkt.extract(hdr.scion.dst_host_16);
        counter.decrement(4);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0x0f: src_host_4;
            0x03 &&& 0x0f: src_host_16;
        }
    }

    state dst_host_16_discard {
        pkt.extract(hdr.scion.dst_host_16);
        counter.decrement(4);
        transition select (hdr.scion.common.host_type_len) {
            0x00 &&& 0x0f: src_host_4_discard;
            0x03 &&& 0x0f: src_host_16_discard;
        }
    }

    state src_host_4 {
        pkt.extract(hdr.scion.src_host_4);
        counter.decrement(1);
        transition path;
    }

    state src_host_4_discard {
        pkt.extract(hdr.scion.src_host_4);
        counter.decrement(1);
        transition path_discard;
    }

    state src_host_16 {
        pkt.extract(hdr.scion.src_host_16);
        counter.decrement(4);
        transition path;
    }

    state src_host_16_discard {
        pkt.extract(hdr.scion.src_host_16);
        counter.decrement(4);
        transition path_discard;
    }

    //////////
    // Path //
    //////////

    state path {
        transition select (hdr.scion.common.path_type) {
            sc_path_type.SCION: scion_path;
            default           : accept;
        }
    }

    state path_discard {
        transition select (hdr.scion.common.path_type) {
            sc_path_type.SCION: scion_path_discard;
            default           : accept;
        }
    }

    state scion_path {
        pkt.extract(hdr.path.meta);
        counter.decrement(SC_PATH_META_BYTES / 4);
        transition select (hdr.path.meta.seg1_len, hdr.path.meta.seg2_len) {
            (0, 0) : info_field_1;
            (_, 0) : info_field_2;
            default: info_field_3;
        }
    }

    state scion_path_discard {
        pkt.extract(hdr.path.meta);
        counter.decrement(SC_PATH_META_BYTES / 4);
        transition select (hdr.path.meta.seg1_len, hdr.path.meta.seg2_len) {
            (0, 0) : info_field_1_discard;
            (_, 0) : info_field_2_discard;
            default: info_field_3_discard;
        }
    }

    @critical
    state info_field_1 {
        pkt.extract(hdr.path.info0);
        counter.decrement(SC_INFO_FIELD_BYTES / 4);
        transition hop_fields;
    }

    @critical
    state info_field_1_discard {
        pkt.extract(hdr.path.info0);
        counter.decrement(SC_INFO_FIELD_BYTES / 4);
        transition hop_fields_discard;
    }

    @critical
    state info_field_2 {
        pkt.extract(hdr.path.info0);
        pkt.extract(hdr.path.info1);
        counter.decrement(2 * SC_INFO_FIELD_BYTES / 4);
        transition hop_fields;
    }

    @critical
    state info_field_2_discard {
        pkt.extract(hdr.path.info0);
        pkt.extract(hdr.path.info1);
        counter.decrement(2 * SC_INFO_FIELD_BYTES / 4);
        transition hop_fields_discard;
    }

    @critical
    state info_field_3 {
        pkt.extract(hdr.path.info0);
        pkt.extract(hdr.path.info1);
        pkt.extract(hdr.path.info2);
        counter.decrement(3 * SC_INFO_FIELD_BYTES / 4);
        transition hop_fields;
    }

    @critical
    state info_field_3_discard {
        pkt.extract(hdr.path.info0);
        pkt.extract(hdr.path.info1);
        pkt.extract(hdr.path.info2);
        counter.decrement(3 * SC_INFO_FIELD_BYTES / 4);
        transition hop_fields_discard;
    }

    state hop_fields {
        // pkt.extract(hdr.path.first_hf);
        transition accept;
    }

    state hop_fields_discard {
        // pkt.extract(hdr.path.first_hf);
        // Subtract one HF so that the last one remains to be extracted
        counter.decrement(SC_HOP_FIELD_BYTES / 4);
        transition discard_hfs;
    }

    state discard_hfs {
        pkt.advance(8 * SC_HOP_FIELD_BYTES);
        counter.decrement(SC_HOP_FIELD_BYTES / 4);
        transition select (counter.is_zero()) {
            false: discard_hfs;
            true : last_hf;
        }
    }

    state last_hf {
        pkt.extract(meta.last_hf);
        transition l4;
    }

    ///////////////////
    // Inner Headers //
    ///////////////////

    state l4 {
        transition select (hdr.scion.common.next_hdr) {
            ip_proto_t.TCP : tcp;
            ip_proto_t.UDP : udp;
            ip_proto_t.SCMP: scmp;
        }
    }

    state scmp {
        pkt.extract(hdr.scmp);
        meta.l4_dst_port = 0;
        transition accept;
    }
}
