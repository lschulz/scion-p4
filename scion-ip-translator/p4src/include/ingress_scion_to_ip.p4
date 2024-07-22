// SPDX-License-Identifier: AGPL-3.0-or-later

// SCION to IP Translation
control ScionToIp(
    inout ingress_headers_t                         hdr,
    inout ingress_metadata_t                        meta,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    apply {
    }
}
