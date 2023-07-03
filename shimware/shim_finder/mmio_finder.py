import angr
import sys
import threading
import nose
#import dive
from .dynamic_taint.taint_tracking import *
from .dynamic_taint.dfs import DFS
from .dynamic_taint.deadendinator import TheDeadendinator
from ..loaders.generic import load_it, cfg_it
#from pyvex.lifting.gym import ARMSpotter
from multiprocessing.pool import Pool as Pool
from threading import Timer
import logging
import gc
import argparse

def auto_int(x):
    return int(x, 0)

def parse_opts():
    o = argparse.ArgumentParser()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--single", type=auto_int)
    o.add_argument("--nprocs", type=auto_int, default=1)
    o.add_argument("--timeout", type=auto_int, default=600)
    o.add_argument("--no_cfg", action='store_true')
    o.add_argument("--ifl", type=int, default=0)
    o.add_argument("--dfs-states", type=auto_int, default=1)
    o.add_argument("--base_addr", type=auto_int, default=0x100000)
    o.add_argument("--entry_point", type=auto_int, default=0x100000)
    o.add_argument("--arch", default="ARMEL")
    o.add_argument("binary")
    # TODO: Integrate a control for autoblob here
    opts = o.parse_args()
    return opts

# TODO: Make this configurable from the commandline
MMIO_RANGES= [(0x10000000, 0x20000000),
              (0x40000000, 0x50000000),
              (0x8000000, 0x9000000)]

# TODO: Make angr move the stack somewhere else
STACK_RANGES = [(0x70000000, 0x80000000)]


lck = threading.Lock()
mmio_log = open("mmio_log", 'w')
def write_mmio_log(oper, func_addr, inst_addr, op_addr, op_val=""):
    # thread-safe logging
    try:
        lck.acquire()
        mmio_log.write(", ".join([hex(func_addr), hex(inst_addr), oper, op_addr, op_val]) + "\n")
        mmio_log.flush()
    finally:
        lck.release()


def is_messy_expr(expr):
    d = expr.depth
    if expr.op == "Reverse" or expr.op == "Extract":
        # Hack: angr adds extra reverses/extracts we don't care about
        d -= 1
    return d >= 2


def is_mmio_address(addr):
    for s, e in MMIO_RANGES:
        if s <= addr < e:
            return True
    return False


def is_stack_address(state, addr):
    # TODO: Replace with EDG's idea for automatic stack location finding!
    sp = state.solver.eval(state.regs.sp)
    if abs( sp - addr) < 0x100000:
        return True
    return False

# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")


def mmio_detector(opts, p, f_addr, n_funcs=0, tot_funcs=0):
    mmio_read = threading.Event()
    mmio_write = threading.Event()
    mmio_dma_read = threading.Event()
    mmio_dma_write = threading.Event()
    write_instrs = []
    read_instrs = []
    dma_read_instrs = []
    timed_out = threading.Event()
    errored = threading.Event()

    ##
    ## Taint Policy
    ##

    def mem_read_before(state):
        ip = state.addr
        # If we are dereferencing a value read from MMIO, that's probably a DMA read.
        if is_tainted(state.inspect.mem_read_address, state=state) and ip not in dma_read_instrs:
            l.info("[%#08x] Suspected DMA read found at %#08x, addr %s" % (f_addr, ip, repr(state.inspect.mem_read_address)))
            mmio_dma_read.set()
            dma_read_instrs.append(ip)
            write_mmio_log('DMA_READ', f_addr, ip, repr(state.inspect.mem_read_address))
            return
        addr_sym = state.inspect.mem_read_address
        addr = state.solver.eval(addr_sym)
        if not addr_sym.concrete:
            return
        # If we are reading from an MMIO address, this is of course an MMIO read, and we should
        # taint the value for later
        if is_mmio_address(addr):
            # EDG: We don't care about the read until we see what we do with the data!
            #l.info("[%#08x] MMIO read found to %#08x at %#08x" % (f_addr, addr, ip))
            apply_taint(state, addr, "mmio_read_%s" % hex(addr), bits=32)

    # HACK: Ugh...
    # FIXME: Stack variables
    function_arg_taints = ['reg_r0',
                           'reg_r1',
                           'reg_r2',
                           'reg_r3']

    def mem_write_before(state):
        ip = state.addr
        expr = state.inspect.mem_write_expr
        if not state.inspect.mem_write_address.concrete:
            # We're writing somewhere.... interesting
            addr = state.inspect.mem_write_address
            for tb in function_arg_taints:

                if is_tainted(addr, state=state, taint_buf=tb): #HACK: Ugh...
                    # We're writing to a function argument!
                    if is_tainted(expr, state=state) and ip not in write_instrs:
                        write_mmio_log('MMIO_READ', f_addr, ip, repr(addr), repr(expr))
                        mmio_read.set()
                        write_instrs.append(ip)
        else:
            addr = state.solver.eval(state.inspect.mem_write_address)
            if is_mmio_address(addr):
                if not is_messy_expr(expr) and not expr.concrete and not is_tainted(expr, state=state) and not ip in write_instrs:
                    l.info("[%#08x] MMIO write found to %#08x at %#08x: %s" % (f_addr, addr, ip, repr(expr)))
                    write_instrs.append(ip) # Only alert the same instr once
                    mmio_write.set()
                    write_mmio_log('MMIO_WRITE', f_addr, ip, repr(state.inspect.mem_read_address))
                    # TODO: Fix DMA write detection
                    # if ct.is_tainted(state, state.inspect.mem_write_expr):
                    #    l.info("Possible DMA write to %#08x at %#08x" % (addr, ip))
                    #    mmio_dma_write = True

            # If we are writing out tainted data, that's a useful MMIO read operation
            if is_tainted(expr, state=state) and not is_mmio_address(addr) and not is_stack_address(state, addr):
                if not is_messy_expr(expr) and not ip in read_instrs:
                    l.info("[%#08x] Wrote MMIO data to %#08x at %#08x: %s" % (f_addr, addr, ip, repr(expr)))
                    write_mmio_log('MMIO_READ', f_addr, ip, hex(addr), repr(expr))
                    mmio_read.set()
                    read_instrs.append(ip)
            # TODO: We should taint addresses used to write memory, so we can find DMA writes

    def exit_before(state):
        ip = state.addr
        #target = state.solver.eval(state.inspect.exit_target)
        # TODO make this better

        ret_val_expr = state.regs.r0
        jk = state.inspect.exit_jumpkind
        if jk == 'Ijk_Ret':
            if is_tainted(state.regs.r0, state=state) and not is_messy_expr(ret_val_expr):
                l.info("[%#08x] Returning MMIO data to %#08x" % (f_addr, ip))
                write_mmio_log('MMIO_READ', f_addr, ip, "RET", repr(ret_val_expr))
                mmio_read.set()

    l.warning("Analyzing %#08x (%d / %d)" % (f_addr, n_funcs, tot_funcs))
    tt = TaintTracker(interfunction_level=opts.ifl, precise_argument_check=False, taint_deref_values=False)
    # NOTE: We set taint_deref_values to false here; if we dereference a tainted value (e.g., DMA) we do not
    # care what derefs happen based on this data (e.g., accessing a structure in DMA) We already found the DMA buffer!

    def timeout():
        l.warning("TIMEOUT %#08x" % f_addr)
        tt.stop()
        timed_out.set()

    # prepare the state
    state = p.factory.call_state(f_addr)
    simgr = p.factory.simgr(state)
    
    # Hook up the taint tracker
    tt.add_callback(mem_read_before, 'mem_read', angr.BP_BEFORE)
    tt.add_callback(mem_write_before, 'mem_write', angr.BP_BEFORE)
    tt.add_callback(exit_before, 'exit', angr.BP_BEFORE)
    
    # Intuition: IO functions that use loops will do the IO 
    # regardless of how many times they loop!
    # Therefore, we explore loops only once.
    tt._N = 1
    simgr.use_technique(tt)

    # Optimization: keep only `num_states` states alive.
    # Try not to run out of memory too fast.
    dfs = DFS(num_states=opts.dfs_states)
    simgr.use_technique(dfs)

    # Optimization: If we deadend, who cares, get that stuff out of memory ASAP
    simgr.use_technique(TheDeadendinator())

    # Start the timer
    timer = Timer(opts.timeout, timeout)
    timer.start()
    
    try:
        simgr.run()
    except:
        l.exception("Error analyzing %#08x" % f_addr)
        errored.set()
    timer.cancel()
    return f_addr, mmio_read.is_set(), mmio_write.is_set(), mmio_dma_read.is_set(), mmio_dma_write.is_set(), timed_out.is_set(), errored.is_set()

def setup_logging():
    global l
    logging.basicConfig()
    l = logging.getLogger("MMIOFinder")
    if opts.debug:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)
    logfile = logging.FileHandler("./mmio_finder.log")
    l.addHandler(logfile)
    shut_up("TaintTracking")
    shut_up("angr.engines.vex.engine")
    shut_up("angr.engines.successors")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("pyvex.lifting.gym.arm_spotter")
    

if __name__ == '__main__':
    opts = parse_opts()
    fname = opts.binary 
    setup_logging()
    p = load_it(fname, opts.arch, opts.base_addr, opts.entry_point)
    if not opts.no_cfg and not opts.single:
        cfg = cfg_it(p)
    mmio_reads = []
    mmio_writes = []
    mmio_dma_reads = []
    timeouts = []
    errors = []
    if opts.single:
        print(mmio_detector(opts, p, opts.single, 0, 1))
        sys.exit()
    else:
        N = len(p.kb.functions.keys())
        try:
            mypool = Pool(processes=opts.nprocs)
            func_addrs = p.kb.functions.keys()
            results = [mypool.apply_async(mmio_detector, (opts, p, f, n, N)) for n, f in enumerate(func_addrs)]
            for r in results:
                f, did_read, did_write, did_dma_read, did_dma_write, timed_out, errored = r.get()
                gc.collect()
                if did_read:
                    mmio_reads.append(f)
                if did_write:
                    mmio_writes.append(f)
                if did_dma_read:
                    mmio_dma_reads.append(f)
                if timed_out:
                    timeouts.append(f)
                if errored:
                    errors.append(f)
        except KeyboardInterrupt:
            pass
