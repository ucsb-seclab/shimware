import os
import shutil
import logging
import subprocess
from tempfile import mkdtemp
from .specializer import Specializer, register_specializer
from .common import bytes_to_word, word_to_bytes


l = logging.getLogger(__name__)

HERE = os.path.abspath(".")

def parse_version(raw):
    version = tuple(map(int, raw.strip().split(b".")))
    if len(version) != 3:
        raise ValueError("Invalid version: %r" % raw)
    return version

def update_version_file(name, version):
    with open(name, "w") as f:
        major, minor, rev = version
        rev += 1
        minor += rev // 256
        major += minor // 256
        rev %= 256
        minor %= 256
        major %= 256
        f.write(".".join(map(str, (major, minor, rev))))

def fix_checksum(input_file, mid_file, output_file):
    crc_prog = os.path.join(HERE, "./crc_fixer/AllenBradlyCRC32/bin/")
    subprocess.check_call(["java",
                           "AllenBradlyCRC32Generator",
                           "-f", input_file,
                           "-o", mid_file],
                          cwd=crc_prog)

    sum_prog = os.path.join(HERE, "./crc_fixer/AllenBradlyCkSum/bin/")
    subprocess.check_call(["java",
                           "AllenBradlyCkSumGenerator",
                           "-ctrl",
                           "-f", mid_file,
                           "-o", output_file],
                          cwd=sum_prog)

    os.unlink(input_file)
    os.unlink(mid_file)

class PLCSpecializer(Specializer):
    name = "PLC"

    def default_base(self):
        return 0x100000

    def default_scratch(self):
        return 0x370800

    def adapt_arg_parser(self, p):
        p.add_argument("--nvs",
                       help="NVS template file",
                       default=os.path.join(HERE, "data/nvs-template.txt"))
        p.add_argument("--crc-fixer",
                       help="CRC fixer directory",
                       default=os.path.join(HERE, "crc_fixer/"))

        version_group = p.add_mutually_exclusive_group()
        version_group.add_argument("--version",
                                   help="New firmware version (format: x.x.x)")
        version_group.add_argument("--version-file",
                                   help="New firmware version file (format: x.x.x)",
                                   default=os.path.join(HERE, "data/version.txt"))

        p.add_argument("--no-update-version",
                       help="Don't increment the version number in the version file",
                       action="store_false",
                       dest="update_version")

    def make_branch(self, src, dest):
        return (b"\xEA" + struct.pack(">I", ((dest - (src + 8)) >> 2) & 0xFFFFFFFF)[1:])[::-1]

    def finalize(self, args, prog_bytes):
        if args.version:
            raw_version = args.version
        else:
            with open(args.version_file, "rb") as f:
                raw_version = f.readline()
        if not raw_version:
            l.warn("Version not specified, defaulting to 1.2.3")
            version = (1,2,3)
        else:
            version = parse_version(raw_version)
            if args.update_version and not args.version:
                l.info("Updating version file.")
                update_version_file(args.version_file, version)

        l.info("Patching version.")
        prog_bytes.patch(args.base + 4, chr(version[0]) + chr(version[1]) + chr(version[2]) + "\x00")

        final_prefix = "PN-%d-%d-%d" % version
        final_bin = final_prefix + ".bin"
        final_nvs = final_prefix + ".nvs"

        l.info("Creating temp directory.")
        tmp_dir = mkdtemp(prefix="shimware-plc-")

        input_file  = os.path.join(tmp_dir, "bad_checksum.bin")
        mid_file    = os.path.join(tmp_dir, "mid_checksum.bin")
        output_file = os.path.join(tmp_dir, final_bin)

        l.info("Writing out bad checksum version to file.")
        with open(input_file, "wb") as f:
            f.write(prog_bytes.backing)

        l.info("Fixing checksums.")
        fix_checksum(input_file, mid_file, output_file)

        l.info("Fixing NVS.")
        with open(args.nvs, "r") as f:
            old_nvs = f.read()

        fixed_nvs = old_nvs.format(version=("%d.%d.%d" % version),
                                   major=version[0],
                                   minor=version[1],
                                   file_size=len(prog_bytes.backing),
                                   file_name=final_bin)

        with open(os.path.join(tmp_dir, final_nvs), "w") as f:
            f.write(fixed_nvs)

        l.info("Copying NVS to output directory.")
        shutil.copy(os.path.join(tmp_dir, final_bin), os.path.join(args.out_dir, final_bin))
        shutil.copy(os.path.join(tmp_dir, final_nvs), os.path.join(args.out_dir, args.out_dir))

        l.info("Removing temp directory.")
        shutil.rmtree(tmp_dir)

        l.info("Finished generating version %d.%d.%d." % version)


register_specializer(PLCSpecializer)
