from typing import Dict
from datetime import datetime

from scapy_scion.layers.scion import SCIONPath, InfoField, HopField
from controller.scion import IsdAsn
from controller.daemon_client import DaemonClient

TC_DEFAULT = 0
TC_REALTIME = 1
TC_BACKGROUND = 2


class EmptyPath(Exception):
    pass

class Unreachable(Exception):
    pass


class PathManager:
    def __init__(self, sciond: str):
        self.client = DaemonClient(sciond)
        self.local_ia = self.client.rpc_as(None).isd_as

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.client.close()

    def get_paths(self, dest: IsdAsn) -> Dict[int, SCIONPath]:
        paths = self.client.rpc_paths(self.local_ia, int(dest)).paths
        raise Unreachable("no path to destination")

    def maintain(self):
        pass
