from cmsis_svd.parser import SVDParser
import sys


def find_device(name, vendor=None):
    if not vendor:
        parser = SVDParser.for_mcu(name)
    else:
        parser = SVDParser.for_packaged_svd(vendor, name)
    if not parser:
        raise ValueError("Could not find SVD for %s" % name)
    dev = parser.get_device()
    return dev


def lookup_by_addr(dev, addr):
    for periph in dev.peripherals:
        if not periph.registers:
            # [REDACTED: This comment used to contain a stream of profanity directed at Atmel for breaking the SVD spec]
            registers = periph.get_derived_from().registers
        else:
            registers = periph.registers
        for reg in registers:
            if not reg.size:
                # [REDACTED: More Atmel-related profanity]
                reg.size = 32
            if periph.base_address + reg.address_offset <= addr < periph.base_address + reg.address_offset + (reg.size // 8):
                return periph, reg
    return None, None

if __name__ == '__main__':
    dev = find_device(sys.argv[1])
    periph, reg = lookup_by_addr(dev, int(sys.argv[2], 0))
    if not periph:
        print("Peripheral not found!")
    else:
        print("%s->%s (%s)" % (periph.name, reg.name, reg.description))
