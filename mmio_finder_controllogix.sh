#!/bin/sh
python -m shimware.shim_finder_ng.mmio_finder --nprocs 4 \
--base_addr 0x100000 --entry_point 0x100000 \
--mmio-region 0x08000000 0x09000000 \
--mmio-region 0x0c000000 0x0d000000 \
--mmio-region 0x40000000 0x50000000 \
./firmware/ab_controllogix/PN-337140.bin
