from typing import Dict
from datetime import datetime

from scapy_scion.layers.scion import SCIONPath, InfoField, HopField
from controller.scion import IsdAsn
from controller.path_manager import *


class MockPathManager:
    paths = {
        "0:0:fc01": SCIONPath(Seg0Len=2, Seg1Len=0, Seg2Len=0,
            InfoFields = [
                InfoField(Flags="C", SegID=0xffff, Timestamp=datetime.fromtimestamp(1721748372))
            ],
            HopFields = [
                HopField(ConsIngress=0, ConsEgress=1, MAC=0x111111111111),
                HopField(ConsIngress=2, ConsEgress=0, MAC=0x222222222222)]
        ),
        "0:0:fc02": SCIONPath(Seg0Len=2, Seg1Len=2, Seg2Len=2,
            InfoFields = [
                InfoField(Flags="", SegID=0xffff, Timestamp=datetime.fromtimestamp(1721748372)),
                InfoField(Flags="", SegID=0xeeee, Timestamp=datetime.fromtimestamp(1721748372)),
                InfoField(Flags="C", SegID=0xdddd, Timestamp=datetime.fromtimestamp(1721748372))

            ],
            HopFields = [
                HopField(ConsIngress=7, ConsEgress=0, MAC=0x111111111111),
                HopField(ConsIngress=0, ConsEgress=2, MAC=0x222222222222),
                HopField(ConsIngress=3, ConsEgress=0, MAC=0x333333333333),
                HopField(ConsIngress=0, ConsEgress=8, MAC=0x444444444444),
                HopField(ConsIngress=0, ConsEgress=9, MAC=0x555555555555),
                HopField(ConsIngress=1, ConsEgress=0, MAC=0x666666666666)]
        ),
        "0:0:fc03": SCIONPath(Seg0Len=63,
            InfoFields = [
                InfoField(Flags="C", SegID=0xffff, Timestamp=datetime.fromtimestamp(1721748372)),
            ],
            HopFields = [HopField(ConsIngress=0, ConsEgress=i+1, MAC=0xffffffffffff) for i in range(62)]
                + [HopField(ConsIngress=63, ConsEgress=0, MAC=0xffffffffffff)]
        ),
    }

    def __init__(self, local_ia: IsdAsn):
        self.local_ia = local_ia

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        pass

    def get_paths(self, dest: IsdAsn) -> Dict[int, SCIONPath]:
        if dest == self.local_ia:
            raise EmptyPath("destination is local AS")
        if dest == IsdAsn("1-0:0:fc01"):
            path = self.paths["1-0:0:fc01"]
            return {
                TC_DEFAULT: path,
                TC_REALTIME: path,
                TC_BACKGROUND: path
            }
        elif dest == IsdAsn("1-0:0:fc02"):
            path = self.paths["1-0:0:fc02"]
            return {
                TC_DEFAULT: path,
                TC_REALTIME: path,
                TC_BACKGROUND: path
            }
        elif dest == IsdAsn("1-0:0:fc03"):
            path = self.paths["1-0:0:fc03"]
            return {
                TC_DEFAULT: path,
                TC_REALTIME: path,
                TC_BACKGROUND: path
            }
        else:
            raise Unreachable("no path to destination")

    def maintain(self):
        pass
