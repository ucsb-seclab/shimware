import os
import struct
import logging


l = logging.getLogger(__name__)

class Specializer:
    name = ""

    def default_base(self):
        return None

    def default_scratch(self):
        return None

    def adapt_arg_parser(self, p):
        pass

    def make_branch(self, src, dest):
        pc = src + 4
        offset = dest - pc
        if (abs(offset) & 0xffffff) != abs(offset):
            raise ValueError("Jump out of range: %08x to %08x" % (src, dest))
        out = 0xf0009000
        offset += 1 << 24
        out |= (offset >> 1) & 0x000007ff
        out |= (offset << 4) & 0x03ff0000
        s = ~(offset >> 24) & 1
        out |= (s << 26) & 0x04000000
        i2 = (~(offset >> 22) ^ s) & 1
        out |= (i2 << 11) & 0x00000800
        i1 = (~(offset >> 23) ^ s) & 1
        out |= (i1 << 13) & 0x00002000
        return struct.pack("<HH", (out & 0xffff0000) >> 16, out & 0xffff)

    def finalize(self, args, prog_bytes):
        l.info("Writing output file.")
        with open(os.path.join(args.out_dir, "shimmed.bin"), "wb") as f:
            f.write(prog_bytes.backing)


_known_specializers = {}

def register_specializer(spec):
    _known_specializers[spec.name.lower()] = spec

def get_specializer(name):
    return _known_specializers[name.lower()]

def get_specializers():
    return _known_specializers.keys()

register_specializer(Specializer)
