#!/bin/sh
python -m shimware.shim_finder.mmio_finder --nprocs 4 --base_addr 0xc8000000 --entry_point 0xc8000000 ./firmware/omnipod_pdm/flash.bin
