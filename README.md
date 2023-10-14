# Shimware: Practical firmware shimming

These scripts and utilities help the analyst in performing security retrofitting of embedded firmware.
This includes finding where to insert a shim, where to get the data to make security decisions, as well as actually modifying the firmware (shimmer).

## Author's Note

What follows is the source code companion to "Shimware: Toward Practical Security Retrofitting for Monolithic
  Firmware Images" (RAID 2023). [Read it here.](https://sites.cs.ucsb.edu/~vigna/publications/2023_RAID_Shimware.pdf)  This code was originally written back in 2020, and thanks to the intervening global situation, took some time to see the light.
In order to actually pull off the retrofitting we described in the paper, we needed to make significant improvements to angr, the program analysis library we use throughout this repo.  Thankfully, we were, at the time, also the developers of angr, and a lot of what you don't see in this repo has been upstreamed into angr itself, including a major overhaul of its ARM support, better handling of raw firmware images, and so on. The analyses we wrote here, partiually due to the totally real, as-found-in-the-wild samples we used, are basically a brutal stress test of angr, and are not for the faint of heart or the RAM-constrained.

The angr team continues to make strides in its support for firmware images, but your mileage may vary with your own samples.
Report any crashes coming from within angr itself to the nice folks at [angr.io](https://angr.io/)

## Video

Check out a video of how we shimmed the PLC from the paper [here](https://youtu.be/7Nr5E7xbCGg)

## Contents

* `shimware`: The code of shimware itself

* `shim_finder*` / `location_finder*` / `selfcheck_finder*` / `shimmer`: Helper scripts to run each stage of the shimware pipeline.  As we outline in the paper, these three "finder" tools give us the inputs needed to run `shimmer` which actually modifies the firmware image. These include variants for our three case study images, and are great examples for using this system with your own.

* `shimdata`: These are the "shims" themselves -- the manually-created retrofit, which we are trying to insert.  We include the three case studies that we discuss in the paper here -- including a ton of extra debugging payloads used during the creation of this system that aren't needed for a simple patch.

### Where's the firmware?
Sadly, the case studies we present in the paper involve firmware we ripped out of real devices, and therefore have murky, ambiguous copyright and distribution situations around them.  For the sake of keeping this code here, we're omitting those, but if you're a researcher working with firmware, email us (contact info at the top of the paper) and we'll gladly help you out.

## Installation

### Prerequisites
Shimware requires `angr` and its numerous dependencies.
Please install angr via one of the methods documented on [http://angr.io/]
However, we strongly encourage using [angr-dev | http://github.com/angr/angr-dev] to install angr, as this is a research prototype, which benefits from the latest angr improvements. As such, we do not include angr as a setuptools dependency, you'll want to deal with that yourself (e.g., to have proper Unicorn support)

These tools have only been tested on Linux, particularly Ubuntu 18.04 and 20.04.

`shimmer` requires an ARM compiler, to build the shim payloads from C code.
On Ubuntu, you can get one via: `apt install gcc-arm-none-eabi binutils-arm-none-eabi`

Finally, to install the shimware package itself, do the following:

`pip3 install -e .`


## MMIO Finder

This tool finds sources of data from external IO, which are required to make security decisions in retrofitted firmware.
This tool uses dynamic taint tracking to follow data flows, and is therefore *extremely memory-intensive*. It will also take some time, for larger firmware.

The MMIO Finder tool can be found as the `mmio_finder` script.
Available options can be queried with the `--help` option.

The options required to perform an analysis are the `--base_addr`, `--entry_point`, and `--arch` options, which specifiy the binary's base address, entry point, and architecture specificially.

The analysis can be run across multiple cores, using the `--nprocs` option.
However, this also multiplies its memory footprint.

The tool produces `mmio_log`, a file which lists the detected IO function, instruction address of the IO, which IO operation was performed (read/write) and an expression for the data being read or written.

This data can be coupled with chip datasheets to quickly classify IO functions, or used in a dynamic analysis to manually classify sources of IO.

For examples of how to use the MMIO Finder on real firmware, see the `mmio_finder_*.sh` scripts included in this repository.

## Location Finder

This tool finds space for your retrofit payloads, either space that we are pretty sure is empty (by checking for references to it), or functions that are conservatively safe to overwrite with our firmware modifications.

The tool is run via the `location` script.

The options and usage are identical to the MMIO finder.

The tool produces a file `location_log` with the list of proven-safe function adresses or empty regions, and their sizes, in it.

For examples, see `location_finder_controllogix.sh`

## Self-check Finder

## Shimmer

Shimmer is responsible for actually modifying the firmware.

Shimmer works by injecting "trampolines" into the patch payload, copied to the previously-detected empty locations. Instructions that need to be hooked are then replaced with jumps to these trampolines.

These trampolines then "bounce" execution to they payload's content -- custom handlers written in C or ARM assembly. Example implementations of a debugger (written in assembly) and a network firewall (written in C) are included in the `debugger` directory. (The patcher automatically calls `make` in this directory at the start of every build.)

In order to specify addresses to be hooked, a simple configuration interface is provided in the `shimdata/jumpouts.txt` file. It contains a series of mappings from the virtual (in-memory) address of a particular instruction (the hook location) to the name of a symbol in the C/ARM build described above (the hook destination). For example, the following line would add a hook at address `0x174BF4` to the symbol `network_filter`:

`0x174BF4:"network_filter"`.

Lines beginning with `#` are ignored and can be used as comments.

Keep in mind that the instruction to be hooked is copied to the end of the trampoline so that it is executed after the hook destination is called. **Therefore, do not hook any instruction that depends on the program counter, e.g. jumps or relative loads.** If you're using the output of mmio_finder above, this should't happen.

A similar interface is provided in the `data/patches.txt` file, but for simple byte-replacement patches. In this file, the string specified will simply be used to overwrite the bytes at the given virtual address. For example, the following line would overwrite four bytes at `0x0016F8B0` with `\x0E\xF0\xA0\xE1` (a ret instruction): `0x0016F8B0: "\x0E\xF0\xA0\xE1"`. Comments are supported in a similar fashion to the jumpouts file.

## Example: Controllogix Firewall

The firewall is configured from a simple YAML interface in `debugger/firewall.yml`. The format is as follows: a list of rules are specified; each rule includes a filtering function (`filter`), the arguments to that function (`args`), and a set of actions to be taken when the filter matches (`on_match`), the filter does not match (`on_nomatch`), or the filter returns an error (`on_error`). There are three possible actions: CONTINUE, which continues running the firewall from the next rule, ACCEPT, which returns from the firewall and accepts the packet, and DROP, which returns from the firewall but does not let the firmware handle the packet. (Note: DROP is not yet implemented.) If an action is not specified for any of the three states, the rule defaults to CONTINUE.

Adding more filters is done via additions to `debugger/network_filters.c`. Filters must conform to the standard `filter_function_t` interface as defiend in `debugger/network_filters.h`. Once defined, they must be added to the filter table in `debugger/network_filter.c`. Finally, they must be described in `debugger/filter_descriptors.yml` so that the firewall compiler understand how to parse rules that use the filter: The `index` attribute corresponds to the index of the filter in the array in `debugger/network_filter.c`, and the params specify the type and name of each argument.

### Uploading Patched Firmware for ControlLogix

When run, the patcher will output a new `.bin` and a new `.nvs` file. These files can then be placed in ControlFLASH's data directory for the corresponding PLC (in the case of the Controllogix 1756, `C:\Program Files (x86)\ControlFLASH\0001\000E\0039\`) and flashed onto the PLC using the normal firmware update procedure.
