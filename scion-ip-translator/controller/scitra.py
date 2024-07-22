# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
import sys
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import Iterable, Tuple, Union

import bfrt_grpc.client as gc
from scapy.utils import checksum
from scapy_scion.layers.scion import SCIONPath

from controller.path_manager import PathManager, Unreachable
from controller.scion import Asn, IsdAsn

IPAddress = Union[IPv4Address, IPv6Address]

SCION_PREFIX_LEN = 8
SCION_PREFIX = 0xfc << (128 - SCION_PREFIX_LEN)
SCION_NETWORK = IPv6Network((SCION_PREFIX, SCION_PREFIX_LEN))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


def _parse_hex(raw: str, length: int) -> int:
    def parse(raw: str):
        if raw == "":
            return 0, 0
        n = 0
        groups = [int(group, base=16) for group in raw.split(":")]
        for group in groups:
            if 0 <= group <= 0xffff:
                n <<= 16
                n |= group
            else:
                raise ValueError("invalid hex string")
        return n, len(groups)

    n = 0
    parts = raw.split("::")
    if len(parts) > 2:
        raise ValueError(":: may appear only once")

    length_groups = (length + 15) // 16
    n_lo, _ = parse(parts[-1])
    n_hi, groups_hi = parse(parts[-2]) if len(parts) > 1 else (0, 0)

    if length_groups - groups_hi < 0:
        raise ValueError("invalid number of groups")
    n_hi <<= (16 * (length_groups - groups_hi))
    n = n_hi | n_lo
    if n.bit_length() > length:
        raise ValueError("number too large")
    return n


def _format_hex(n: int) -> str:
    assert n >= 0
    groups = max(1, (n.bit_length() + 15) // 16)
    return ":".join(["{:x}".format((n >> (16*(i-1))) & 0xffff) for i in range(groups, 0, -1)])


def encode_isd_asn(ia: IsdAsn) -> Tuple[int, int]:
    """Encode SCION ISD-ASN address"""

    if not 0 <= ia.isd < 2**12:
        raise ValueError("ISD cannot be encoded")
    if int(ia.asn) < 2**19:
        encoded_asn = int(ia.asn)
    elif 0x2_0000_0000 <= int(ia.asn) <= 0x2_0007_ffff:
        encoded_asn = (1 << 19) | (int(ia.asn) & 0x7ffff)
    else:
        raise ValueError("ASN cannot be encoded")

    return ia.isd, encoded_asn


def encode_ia(ia: IsdAsn) -> int:
    """Encode SCION ISD-ASN address to an IPv6 prefix"""
    isd, asn = encode_isd_asn(ia)
    return SCION_PREFIX | (isd << 108) | (asn << 88)


def encode_ipv4(ia: IsdAsn, interface: IPv4Address) -> IPv6Address:
    """Encode SCION ISD-ASN and IPv4 address to SCION-IPv4-mapped IPv6 address"""
    ip = encode_ia(ia)
    ip |= 0xffff << 32
    ip |= int.from_bytes(interface.packed, "big")
    return IPv6Address(ip)


def encode_ipv6(ia: IsdAsn, local_prefix: int, subnet: int, interface: int|str,
                subnet_bits: int = 8) -> IPv6Address:
    """Encode SCION ISD-ASN and IPv6 interface to SCION-mapped IPv6 address"""
    assert local_prefix.bit_length() <= (24 - subnet_bits)
    assert subnet.bit_length() < subnet_bits
    ip = encode_ia(ia)
    ip |= local_prefix << (64 + subnet_bits)
    ip |= subnet << 64
    if isinstance(interface, str):
        ip |= _parse_hex(interface, 64)
    else:
        assert interface < 2**64
        ip |= interface
    return IPv6Address(ip)


def decode_isd_asn(isd: int, asn: int) -> IsdAsn:
    """Decode ISD and ASN"""
    if asn & (1 << 19):
        asn = 0x2_0000_0000 | (asn & 0x7ffff)
    return IsdAsn((isd, Asn(asn)))


def decode_ia(ip: int) -> IsdAsn:
    """Decode ISD-ASN from a SCION-mapped IPv6 address."""
    asn = (ip >> 88) & 0xfffff
    isd = (ip >> 108) & 0xfff
    return decode_isd_asn(asn, isd)


def decode_ipv4(ip: IPv6Address) -> Tuple[IsdAsn, IPv4Address]:
    """Decode a SCION-IPv4-mapped IPv6 address"""
    if not ip in SCION_NETWORK:
        raise ValueError("not a SCION-mapped IPv6 address")

    ip = int(ip)
    ia = decode_ia(ip)
    interface = ip & 0xffff_ffff_ffff_ffff
    prefix = (ip >> 64) & 0xffff_ffff_ffff
    if interface & (0xffffffff << 32) != (0x0000ffff << 32) or prefix != 0:
        raise ValueError("not a SCION-IPv4-mapped IPv6 address")

    return ia, IPv4Address(interface & 0xffff_ffff)


def decode_ipv6(ip: IPv6Address, subnet_bits: int = 8) -> Tuple[IsdAsn, int, int, str]:
    """Decode a SCION.mapped IPv6 address"""
    if not ip in SCION_NETWORK:
        raise ValueError("not a SCION-mapped IPv6 address")

    ip = int(ip)
    ia = decode_ia(ip)
    interface = ip & 0xffff_ffff_ffff_ffff
    subnet = (ip >> 64) & ~(~0 << subnet_bits)
    local_prefix = (ip >> (64 + subnet_bits)) & ~(~0 << (24 - subnet_bits))

    return ia, local_prefix, subnet, _format_hex(interface)


def decode_ip(ip: IPv6Address, subnet_bits: int = 8) -> Tuple[int, int, int, int, Union[IPv4Address, str]]:
    """Decode a SCION-mapped IPv6 address as IPv6 or IPv6"""
    ip = int(ip)
    interface = ip & 0xffff_ffff_ffff_ffff
    prefix = (ip >> 64) & 0xffff_ffff_ffff
    if interface & (0xffffffff << 32) == (0x0000ffff << 32):
        if prefix == 0:
            return decode_ipv4(ip)
    return decode_ipv6(ip, subnet_bits)


class ActionTable:
    """Helper for accessing tables with actions and action data.

    TODO: Add methods for reading table entries and setting default action.
    """
    def __init__(self, table):
        self.table = table
        self._key_field_names = table.info.key_field_name_list_get()
        self._actions = [action.split(".")[-1] for action in table.info.action_name_list_get()]
        self._data_field_names = {
            action: table.info.data_field_name_list_get(action) for action in self._actions}
        self.staged = []

    def _make_key_tuples(self, key: Iterable):
        key_tuples = []
        for name, value in zip(self._key_field_names, key):
            if isinstance(value, dict):
                key_tuples.append(gc.KeyTuple(name, **value))
            else:
                key_tuples.append(gc.KeyTuple(name, value))
        return key_tuples

    def stage_key(self, key: Iterable):
        key_tuples = self._make_key_tuples(key)
        self.stage.append((self.table.make_key(key_tuples), None))

    def stage_entry(self, key: Iterable, data: Iterable, action: str):
        key_tuples = self._make_key_tuples(key)
        data_tuples = [gc.DataTuple(name, value) for name, value in zip(self._data_field_names[action], data)]
        self.staged.append((self.table.make_key(key_tuples), self.table.make_data(data_tuples, action)))

    def reset(self):
        self.staged = []

    def commit_add(self, target):
        keys, data = zip(*self.staged)
        try:
            self.table.entry_add(target, list(keys), list(data))
        finally:
            self.reset()

    def commit_add_or_mod(self, target):
        keys, data = zip(*self.staged)
        try:
            self.table.entry_add_or_mod(target, list(keys), list(data))
        finally:
            self.reset()

    def commit_del(self, target):
        keys, data = zip(*self.staged)
        try:
            self.table.entry_del(target, list(keys))
        finally:
            self.reset()


class Controller:
    """Controller for the SCION-IP translator on Tofino 1 or 2.
    """
    SC_MAX_INFO_CNT = 3
    MAX_HF_PER_PASS = 12

    def __init__(self,
        interface: gc.ClientInterface,
        path_manager: PathManager,
        edge_br: bool = False,
        p4_name: str = "scitra",
        pipe_id: int = 0xffff,
        device_id: int = 0):
        """
        ### Parameters ###
        interface    : gRPC client interface connected to switch driver
        path_manager : SCION path provider.
        edge_br      : Configure Scitra as a SCION border router.
        p4_name      : Name of the P4 program
        pipe_id      : Pipe to control, 0xffff for all pipes.
        device_id    : Usually 0
        """
        self.interface = interface
        self.path_manager = path_manager
        self.p4_name = p4_name
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.device_id = device_id
        self.target = gc.Target(self.device_id, pipe_id)

        self._edge_br = edge_br
        self._as_key = None
        self._local_ia = None
        self._int_interfaces = []
        self._ext_interfaces = []
        self._routers = {}

        logger.info("Program name: %s", self.bfrt_info.p4_name_get())
        self._get_learn_objs()
        self._get_tables()

    def set_local_ia(self, local: IsdAsn):
        """Set the SCION address of the local AS."""
        self._local_ia = local

    def set_key(self, key: bytes):
        """Set the AS hop field verification key. Only valid for BRs."""
        assert self._edge_br
        self._as_key = key

    def add_internal_interface(self, dev_port: int, mac: bytes, ip: IPv6Address):
        """Add an interface to the AS-internal network. IPv6 packets arriving on this interface
        are translated to SCION packets.
        """
        self._int_interfaces.append((dev_port, mac, ip))

    def add_external_interface(self, ifid: int, isd_as: IsdAsn, dev_port: int,
            local: Tuple[bytes, IPAddress, int],
            remote: Tuple[bytes, IPAddress, int]):
        """Add an interface to a border router in another AS. SciTra can only have external interfaces
        if it is operating as a border router.

        ### Paramaters ###
        ifid     : SCION AS interface ID (as encoded in the hop fields).
        isd_as   : ISD-ASN of the other border router.
        dev_port : Device port connected to the other BR.
        local    : (MAC, IP, UDP Port) of the local BR interface.
        remote   : (MAC, IP, UDP Port) of the remote BR interface.
        """
        self._int_interfaces[(isd_as, ifid)] = (dev_port, local, remote)

    def add_border_router(self, br_ip: IPv6Address, br_port: int, dev_port: int, br_mac: bytes, src_mac: bytes):
        """Add a border router in the local AS. If SciTra is working as a transparent translator,
        these are the border routers outgoing packets can be forwarded to.

        ### Paramaters ###
        br_ip    : IP address of the border router. ("internal_addr" in topology.json)
        br_port  : UDP port of the border router. ("internal_addr" in topology.json)
        dev_port : Device port the BR can be reached through.
        br_mac   : MAC address of the next hop towards the BR.
        src_mac  : Source MAC address to use for sending packet to the BR.
        """
        self._routers[(br_ip, br_port)] = (dev_port, br_mac, src_mac)

    def run(self):
        """Run the control plane. Does not return until interrupted by the user."""
        self._init_tables()
        while True:
            self._handle_digests()
            # self.interface.idletime_notification_get(timeout=1)
            # self._remove_unused_paths()
            self.path_manager.maintain()

    def _handle_digests(self, timeout=1):
        for digest in self.interface.digest_get_iterator(timeout=timeout):
            self._handle_path_request(digest)

    def _maintain_paths(self):
        self.path_manager.maintain()

    def _handle_path_request(self, digest):
        """Configure paths to a destination AS."""
        if digest.target.device_id != self.device_id:
            return
        logger.debug("Received digests from pipe %d", digest.target.pipe_id)
        for data in self.path_digest.make_data_list(digest):
            data_dict = data.to_dict()
            dest = decode_isd_asn(data_dict["isd"], data_dict["asn"])
            logger.info("Request for paths to %s", dest)
            try:
                paths = self.path_manager.get_paths(dest)
            except Unreachable:
                self._add_unreachable(dest)
            else:
                for tc, path in paths.items():
                    if self._edge_br:
                        # If we are the BR, insert path with the first HF already validated
                        path.egress(self._as_key)
                    self._add_path(dest, tc, path)

    def _get_learn_objs(self):
        self.path_digest = self.bfrt_info.learn_get("path_digest")
        # self.path_digest.info.data_field_annotation_add("isd", "bytes")
        # self.path_digest.info.data_field_annotation_add("asn", "bytes")

    def _get_tables(self):
        # Ingress Parser
        self.t_recirc_ports = self.bfrt_info.table_get("IgParser.recirc_ports")

        # Ingress
        self.t_ingress = ActionTable(self.bfrt_info.table_get("Ingress.tab_ingress"))

        # Ingress IP to SCION
        self.t_i2s_recirc = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_recirc"))
        self.t_i2s_path_meta = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_path_meta"))
        self.t_i2s_inf = [ActionTable(self.bfrt_info.table_get(f"Ingress.i2s.tab_inf_{i}")) for i in range(self.SC_MAX_INFO_CNT)]
        self.t_i2s_hf = [ActionTable(self.bfrt_info.table_get(f"Ingress.i2s.tab_hf_{i}")) for i in range(self.MAX_HF_PER_PASS)]
        self.t_i2s_classifier = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_classifier"))
        self.t_i2s_src_ia = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_source_ia"))
        self.t_i2s_src_net = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_src_network_map"))
        self.t_i2s_unreachable = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_unreachable"))
        self.t_i2s_path = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_path"))
        self.t_i2s_next_hop = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_next_hop"))
        self.t_i2s_underlay_src = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_underlay_source"))
        self.t_i2s_path_mtu = ActionTable(self.bfrt_info.table_get("Ingress.i2s.tab_path_mtu"))

    def _init_tables(self):
        logger.info("Initializing tables")

        # Ingress Table
        self.t_ingress.stage_entry(( # continue inserting hop fields into recirculated packets
            {"value": 1, "mask": 1}, {"value": 0, "mask": 0}, {"value": 0, "mask": 0},
            {"value": 0, "mask": 0}, {"value": 0, "mask": 0}), [], "scion2ip")
        self.t_ingress.commit_add(self.target)

        # Source IA
        self.t_i2s_src_ia.table.default_entry_set(self.target, self.t_i2s_src_ia.table.make_data([
            gc.DataTuple("isd", self._local_ia.isd),
            gc.DataTuple("asn", int(self._local_ia.asn)),
            gc.DataTuple("encoded_asn", encode_isd_asn(self._local_ia)[1])],
            "set_source_ia")
        )

    def _refresh_paths_to(self, isd, asn):
        pass

    def _add_path(self, tc: int, dest: IsdAsn, path: SCIONPath):
        # TODO
        isd, asn = encode_isd_asn(dest)
        chksum = checksum(bytes(path))

    def _add_unreachable(self, dest: IsdAsn):
        pass
