SCION-IP Translator for Tofino 1 and 2
======================================

### Prerequisites
- Intel P4 Studio (SDE) 9.13.3
- [scapy_scion](https://github.com/lschulz/scapy-scion-int/) must be in `PYTHONPATH`
- Required Python 3 modules:
  - numpy
  - matplotlib
  - pyyaml

### Build
```bash
make
```

### Run model
```bash
sudo $SDE_INSTALL/bin/veth_setup.sh
${SDE}/run_tofino_model.sh --arch tofino -p scitra -f ptf-tests/ports_tf1.json
${SDE}/run_switchd.sh --arch tf1 -p scitra
```

### PTF tests
```bash
${SDE}/run_p4_tests.sh --arch tf1 -f ptf-tests/ports_tf1.json -t ptf-tests
```
