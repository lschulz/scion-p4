# SPDX-License-Identifier: AGPL-3.0-or-later
import time
from ipaddress import IPv4Address, IPv6Address

import bfrt_grpc.client as gc
import ptf
import scapy
from bfruntime_client_base_tests import BfRuntimeTest
from controller.scion import IsdAsn
from controller.scitra import Controller as SciTraCtrl
from controller.scitra import encode_ipv6
from p4testutils.misc_utils import *
from ptf.mask import Mask
from ptf.testutils import group
from scapy.layers.inet6 import IP, UDP, Ether, IPv6
from scapy.packet import Packet, Raw
from scapy_scion.layers.scion import SCION

from mock.path_manager import MockPathManager


def _make_port(pipe: int, port: int) -> int:
    """Make port number from pipe ID and port within the pipe."""
    return (pipe << 7) | port


class IpToScionTest(BfRuntimeTest):
    """Test translating IP packets to SCION and forwarding to the egress BR."""
    client_id = 0
    p4_name = "scitra"

    local_ia = IsdAsn("1-0:0:fc")
    tra_interface = encode_ipv6(local_ia, 1, 0, 1)
    src_mac = "08:00:27:86:6a:04"
    dst_mac = "08:00:27:86:6a:03"
    src_address = "fd00:f00d:cafe::2"
    dst_interface = "21f2:99bf:379d:a5f7"
    ippackets = [
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_address, dst=str(encode_ipv6(IsdAsn("1-0:0:fc01"), 1, 0, dst_interface))) /
        UDP(sport=20000, dport=80) /
        Raw("TEST"),
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_address, dst=str(encode_ipv6(IsdAsn("1-0:0:fc02"), 1, 0, dst_interface))) /
        UDP(sport=20000, dport=80) /
        Raw("TEST"),
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_address, dst=str(encode_ipv6(IsdAsn("1-0:0:fc03"), 1, 0, dst_interface))) /
        UDP(sport=20000, dport=80) /
        Raw("TEST"),
    ]

    tra_mac = "08:00:27:86:6a:02"
    br_mac = "08:00:27:86:6a:01"
    tra_ip = "fc::1"
    br_ip = "fd::1"
    br_port = 30042
    translated = [
        Ether(src=tra_mac, dst=br_mac) /
        IPv6(src=tra_ip, dst=br_ip) /
        UDP(sport=20000, dport=br_port) /
        SCION(
            DstISD=1, DstAS="0:0:fc01",
            SrcISD=1, SrcAS="0:0:fc00",
            DL=16, SL=16,
            DstHostAddr=ippackets[0][IPv6].dst,
            SrcHostAddr=str(encode_ipv6(local_ia, 0xdead, 0, 2)),
            Path=MockPathManager.paths["0:0:fc01"]
        ) /
        Raw("TEST"),
        Ether(src=tra_mac, dst=br_mac) /
        IPv6(src=tra_ip, dst=br_ip) /
        UDP(sport=20000, dport=br_port) /
        SCION(
            DstISD=1, DstAS="0:0:fc02",
            SrcISD=1, SrcAS="0:0:fc00",
            DL=16, SL=16,
            DstHostAddr=ippackets[0][IPv6].dst,
            SrcHostAddr=str(encode_ipv6(local_ia, 0xdead, 0, 2)),
            Path=MockPathManager.paths["0:0:fc02"]
        ) /
        Raw("TEST"),
        Ether(src=tra_mac, dst=br_mac) /
        IPv6(src=tra_ip, dst=br_ip) /
        UDP(sport=20000, dport=br_port) /
        SCION(
            DstISD=1, DstAS="0:0:fc03",
            SrcISD=1, SrcAS="0:0:fc00",
            DL=16, SL=16,
            DstHostAddr=ippackets[0][IPv6].dst,
            SrcHostAddr=str(encode_ipv6(local_ia, 0xdead, 0, 2)),
            Path=MockPathManager.paths["0:0:fc03"]
        ) /
        Raw("TEST"),
    ]

    def setUp(self):
        super().setUp(self.client_id, self.p4_name)
        self.interface.clear_all_tables()
        self.path_manager = MockPathManager(self.local_ia)
        self.controller = SciTraCtrl(self.interface, self.path_manager, False, self.p4_name)

    def tearDown(self):
        super().tearDown()

    def runTest(self):
        self.controller.set_local_ia(self.local_ia)
        self.controller.add_internal_interface(1, self.dst_mac, self.tra_interface)
        self.controller.add_border_router(self.br_ip, self.br_port, 2, self.br_mac, self.tra_mac)
        self.controller._init_tables()

        logger.info("Test path cache miss")
        send_packet(self, 0, self.ippackets[0])
        verify_no_packet_any(self, self.translated[0], ports=[0, 4])

        logger.info("Handle digest")
        self.controller._handle_digests()

        logger.info("Test path cache hit")
        send_packet(self, 0, self.ippackets[0])
        verify_packet(self, self.translated[0], 0, timeout=1)

        # logger.info("Precache paths")

        # logger.info("Insert SCION path (x bytes)")
        # logger.info("Insert SCION path (y bytes)")
        # logger.info("Insert SCION path (z bytes)")

        # logger.info("Test packet too big after translation")


# class BrIpToScionTest(BfRuntimeTest):
#     """Test translating IP packets to SCION and forwarding to another AS."""

#     def setUp(self):
#         super().setUp()

#     def tearDown(self):
#         super().tearDown()

#     def runTest(self):
#         pass
