Cryptographic Algorithms for Tofino 2
=====================================

### [AES-ECB-2Pipes](./aes_2pipes/) and [AES-ECB-1Pipes](./aes_1pipe/)
Encrypt one or two 128-bit blocks with a 128-bit key using AES in ECB mode.
The key is expanded dynamically in the data plane and can be different for every
packet.

### [AES-CMAC-2Pipes](./cmac_2pipes) and [AES-CMAC-1Pipe](./cmac_1pipe)
Calculate the AES-CMAC of one or two separate 128-bit data blocks and compare
to an expected CMAC provided in the packet. If the CMACs do not match the
expected values the packet is dropped, otherwise it is forwarded to a port read
from the packet header. The AES key expansion and subkey derivation for AES-CMAC
are handled by the control plane.

Building
--------
AES-ECB-1Pipes and AES-ECB-2Pipes only build with SDE 9.13.0. Building with
9.13.3 fails because of the line
`@in_hash { KEY ## .c0 = byte0_b##B ++ byte1_b##B ++ byte2_b##B ++ byte3_b##B; }`
in `aes.p4`.

Contributors
------------
- Lars-Christian Schulz, NetSys Lab OvGU Magdeburg
