import angr
import struct
import re
import pyvex

# Ueful stuff to know
entry_point = 0xC8000000
base_addr = entry_point
i2cwrite_addr = 0xC800ECAC # i2c1_write_char

def load_it():
    p = angr.Project("../../firmware/omnipod_pdm/flash.bin", 
    main_opts={'base_addr': base_addr, 
               'arch': 'ARMEL', 
               'backend': 'blob', 
               'entry_point': entry_point})
    return p


def cfg_it_linear(p):
    #fns = p.analyses.FunctionIdentification().function_addrs
    cfg = p.analyses.CFGFast(function_prologues=True,
                             resolve_indirect_jumps=True,
                             force_complete_scan=False,
                             show_progressbar=True,
                             collect_data_references=True,
                             detect_tail_calls=True)
    return cfg



 

if __name__ == '__main__':
    p = load_it()
    cfg = cfg_it_linear(p)
    import IPython; IPython.embed()
