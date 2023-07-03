import angr
from cle.backends import NamedRegion


# Ueful stuff to know
entry = 0x100000
base = entry
i2cwrite_addr = 1524672 # We think this is i2c write.  We aren't sure.
the_guy = 0x00174B2C
N = 2

def load_it():
    p = angr.Project("./firmware/ab_controllogix/PN-337140.bin", main_opts={'base_addr': 0x100000, 'arch': 'ARMEL', 'backend': 'blob', 'entry_point': 0x100000})
    mmio_regions = [(0x08000000, 0x09000000), # basic MMIO region
                    (0x0c000000, 0x0d000000), # Shared memory w/ Midrange
                    (0x40000000, 0x50000000), # Midrange controller peripheral region
                    ]
    region_count = 0
    for start, end in mmio_regions:
        region = NamedRegion("mmio%d" % region_count, start, end)
        p.loader.dynamic_load(region)
    return p


def cfg_it(p):
    #fns = p.analyses.FunctionIdentification().function_addrs
    cfg = p.analyses.CFGFast(function_prologues=True,
                             resolve_indirect_jumps=True,
                             force_complete_scan=False,
                             show_progressbar=True,
                             cross_references=True,
                             detect_tail_calls=False)
    return cfg


def auto_analyze():
    p = load_it()
    cfg = cfg_it(p)
    ccs = p.analyses.CompleteCallingConventions(recover_variables=False)
    return p, cfg
 

if __name__ == '__main__':
    p = load_it()
    cfg = cfg_it(p)
    import IPython; IPython.embed()
