import os
import re
import struct
import logging
import argparse
import subprocess
from elftools.elf.elffile import ELFFile
from specializers import get_specializer, get_specializers, \
    RelocatedByteArray, bytes_to_word, word_to_bytes


l = logging.getLogger("patch")

HERE = os.path.abspath(".")


def build_interface():
    subprocess.check_call(["make"], cwd=os.path.join(HERE, "interface"))

def parse_addrs_file(name):
    with open(name, "rb") as f:
        return [int(l, 0) for l in f if l.strip() and not l.strip().startswith(b"#")]

def parse_jumpouts_file(name):
    with open(name, "rb") as f:
        lines = [l for l in f if l.strip() and not l.strip().startswith(b"#")]

    parts = [re.match(rb'([0-9a-fA-Fx]*): *\"(.*)\"$', l) for l in lines]
    return {int(m.group(1), 0): m.group(2).decode("unicode_escape") for m in parts}

def parse_patches_file(name):
    with open(name, "rb") as f:
        lines = [l for l in f if l.strip() and not l.strip().startswith(b"#")]

    parts = [re.match(rb'([0-9a-fA-Fx]*): *\"(.*)\"$', l) for l in lines]
    return {int(m.group(1), 0): m.group(2).decode("unicode_escape") for m in parts}

def get_symbols_from_file(name, symbols):
    out = {}
    with open(name, "rb") as f:
        elf = ELFFile(f)
        sym = elf.get_section_by_name(".symtab")
        txt = elf.get_section_by_name(".text")
        txt_base = txt["sh_addr"]

        for s in symbols:
            matches = sym.get_symbol_by_name(s)
            if matches is None:
                raise ValueError("Couldn't find symbol %r" % s)
            if len(matches) > 1:
                raise ValueError("Found multiple symbols for %r" % s)
            out[s] = sym.get_symbol_by_name(s)[0]["st_value"] - txt_base
    return out

def main():
    args, specializer = parse_args()

    l.info("Building interface.")
    build_interface()

    l.info("Reading input files.")
    with open(args.input, "rb") as f:
        prog_bytes = RelocatedByteArray(f.read(), args.base)

    jumpouts = parse_jumpouts_file(args.jumpouts)
    patches = parse_patches_file(args.patches)

    names = set(("trampoline",
                 "trampoline.old_instr", "trampoline.dest_loc",
                 "trampoline.ret_loc", "trampoline.old_pc",
                 "trampoline.end"))

    for symbol in jumpouts.values():
        names.add(symbol)

    l.info("Getting symbols.")
    symbols = get_symbols_from_file(args.interface_elf, names)

    l.info("Reading interface binary.")
    with open(args.interface_bin, "rb") as f:
        interface_bytes = f.read()

    l.info("Performing patches.")
    for location, replacement in patches.items():
        l.info("\t(%#x -> %r)" % (location, replacement))
        prog_bytes.patch(location, replacement)

    l.info("Adding interface binary.")
    prog_bytes.patch(args.scratch, interface_bytes)

    trampoline_bytes = interface_bytes[symbols["trampoline"]:symbols["trampoline.end"]]
    current_trampoline = args.scratch + len(interface_bytes)

    def make_trampoline(old_instr, dest_loc, ret_loc, old_pc):
        base = symbols["trampoline"]
        data = RelocatedByteArray(trampoline_bytes, base)

        data.patch(symbols["trampoline.old_instr"], word_to_bytes(old_instr))
        data.patch(symbols["trampoline.dest_loc"],  word_to_bytes(dest_loc))
        data.patch(symbols["trampoline.ret_loc"],   word_to_bytes(ret_loc))
        data.patch(symbols["trampoline.old_pc"],    word_to_bytes(old_pc))

        return data.backing

    def add_jumpout(src, dest, trampoline_loc):
        tr = make_trampoline(prog_bytes.get_word_at(src),
                             dest,
                             src + 4,
                             src)
        br = specializer.make_branch(src, trampoline_loc)

        prog_bytes.patch(trampoline_loc, tr)
        prog_bytes.patch(src, br)
        next_loc = trampoline_loc + len(tr)
        return next_loc

    l.info("Adding jumpouts.")
    for loc, dest in jumpouts.items():
        dest_loc = args.scratch + symbols[dest]
        l.info("\t(%#x -> %#x (%s) via %#x)" % (loc, dest_loc, dest, current_trampoline))
        current_trampoline = add_jumpout(loc, dest_loc, current_trampoline)

    l.info("Finalizing.")
    specializer.finalize(args, prog_bytes)

def parse_args():
    pre = argparse.ArgumentParser(description="Patch a firmware.",
                                  add_help=False)

    def add_target(t):
        t.add_argument("--target",
                       help="The device to which the firmware belongs; " \
                       + "Options include " \
                       + ",".join(map(repr, get_specializers())),
                       default="")

    add_target(pre)
    specializer = get_specializer(pre.parse_known_args()[0].target)()

    p = argparse.ArgumentParser(description="Patch a firmware.")

    add_target(p)

    p.add_argument("--input",
                   help="Firmware input file",
                   default=os.path.join(HERE, "data/firmware.bin"))
    def_base = specializer.default_base()
    p.add_argument("--base",
                   help="Base address of the firmware",
                   type=lambda x: int(x, 0),
                   **({"default": def_base} if def_base is not None else {"required": True}))
    def_scratch = specializer.default_scratch()
    p.add_argument("--scratch",
                   help="Scratch location in firmware (virtual addr)",
                   type=lambda x: int(x, 0),
                   **({"default": def_scratch} if def_scratch is not None else {"required": True}))

    p.add_argument("--interface-elf",
                   help="Interface elf file",
                   default=os.path.join(HERE, "interface/build/interface.elf"))
    p.add_argument("--interface-bin",
                   help="Interface binary blob",
                   default=os.path.join(HERE, "interface/build/interface.bin"))

    p.add_argument("--jumpouts",
                   help="Jumpouts file",
                   default=os.path.join(HERE, "data/jumpouts.txt"))
    p.add_argument("--patches",
                   help="Patches file",
                   default=os.path.join(HERE, "data/patches.txt"))

    p.add_argument("--out-dir",
                   help="Output directory",
                   default=os.path.join(HERE, "./patched/"))

    specializer.adapt_arg_parser(p)

    args = p.parse_args()

    if bool(args.interface_elf) ^ bool(args.interface_bin):
        p.error("--interface-elf and --interface-bin must be specified together")

    return args, specializer


if __name__ == "__main__":
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    main()
