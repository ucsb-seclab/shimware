#!/bin/sh
python -m shimware.shim_finder_ng.location_finder --nprocs 1 \
--mmio-region 0x08000000 0x09000000 \
--mmio-region 0x0c000000 0x0d000000 \
--mmio-region 0x40000000 0x50000000 \
--resume PN-337140.bin.angrproject \
--logix \
./firmware/ab_controllogix/PN-337140.bin \
$@
