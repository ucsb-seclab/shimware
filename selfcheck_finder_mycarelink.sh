#!/bin/sh
python -m shimware.shim_finder_ng.checksum_finder --nprocs 1 \
--auto \
--mmio-region 0x40000000 0x60000000 \
--mmio-region 0xe0000000 0xe1000000 \
--resume mycarelink-full.bin.angrproject \
./firmware/mycarelink/mycarelink-full.bin \
$@
