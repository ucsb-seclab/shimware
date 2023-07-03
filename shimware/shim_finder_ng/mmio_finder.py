import angr
from angr.errors import SimValueError
import sys
import threading
from .dynamic_taint.taint_tracking import *
from .dynamic_taint.dfs import DFS
from .dynamic_taint.deadendinator import TheDeadendinator
from ..loaders.generic import load_it, cfg_it, get_fullest_init_state, get_magical_init_state
from multiprocessing.pool import Pool as Pool
from threading import Timer
from angr.exploration_techniques import LoopSeer
import logging
import gc
import argparse
import psutil
import claripy
from .svd_lookup import lookup_by_addr, find_device
import re
from .util import *
import os
import pickle
from angr.procedures.libc.abort import abort as Deadend

def auto_int(x):
    return int(x, 0)

def parse_opts():
    global MMIO_RANGES
    o = argparse.ArgumentParser()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--single", type=auto_int)
    o.add_argument("--nprocs", type=auto_int, default=1)
    o.add_argument("--timeout", type=auto_int, default=300)
    o.add_argument("--ifl", type=int, default=0)
    o.add_argument("--dfs-states", type=auto_int, default=1)
    o.add_argument('-I', '--known-io-pointer', dest="io_pointers", action='append',
                   nargs=1, type=auto_int, help="Help the analysis out by designating pointers"
                                                "to known IO-related structs", default=[])
    o.add_argument("--resume")
    o.add_argument("--base_addr", type=auto_int, default=0x100000)
    o.add_argument("--entry_point", type=auto_int, default=0x100000)
    o.add_argument("--arch", default="ARMEL")
    o.add_argument("--logix", action='store_true')
    o.add_argument("--model", help="CPU model to use for SVD lookups (See cmsis-svd docs for a list)")
    o.add_argument('-M','--mmio-region',action='append', nargs=2, type=auto_int)
    o.add_argument('-S','--stack-region', action='append', nargs=2, type=auto_int)
    o.add_argument("--auto", default=False, action="store_true", help="Automatically load the binary, using the autoblob package if available")
    o.add_argument("--profile", action='store_true')
    o.add_argument("--dump-candidates", action='store_true')
    o.add_argument("--load-candidates", action='store_true')
    o.add_argument("binary")

    opts = o.parse_args()
    if opts.mmio_region:
        MMIO_RANGES = opts.mmio_region
    else:
        MMIO_RANGES = [(0x10000000, 0x20000000),
                       (0x40000000, 0x50000000),
                       (0x8000000, 0x9000000)]
    if opts.stack_region:
        STACK_RANGES = opts.stack_region
    return opts

# TODO: Make angr move the stack somewhere else
STACK_RANGES = [(0x70000000, 0x80000000)]

lck = threading.Lock()
mmio_read_re = re.compile(r'.*mmio_read_(\S+)__.*')
def write_mmio_log(state, oper, func_addr, inst_addr, op_addr, op_val="", op_label=""):
    # thread-safe logging
    periph_info = "unknown"

    if "WRITE" in oper:
        if op_addr.concrete:
            op_addr = state.solver.eval_one(op_addr)
            if svd_device:
                periph, reg = lookup_by_addr(svd_device, op_addr)
                if periph and reg:
                    periph_info = "%s->%s (%s, %s)" % (periph.name, reg.name, periph.description, reg.description)
                    # oh come on, who did this...
                    periph_info = periph_info.replace("\n", "")
            op_addr = hex(op_addr)
        op_val = repr(op_val)
    elif 'DMA' in oper:
        # Check the AST for taint.
        m = mmio_read_re.match(repr(op_addr))
        if m:
            op_addr = int(m.group(1), 0)
            if svd_device:
                periph, reg = lookup_by_addr(svd_device, op_addr)
                if periph and reg:
                    periph_info = "%s->%s (%s, %s)" % (periph.name, reg.name, periph.description, reg.description)
                    # oh come on, who did this...
                    periph_info = periph_info.replace("\n", "")
            op_addr = hex(op_addr)
        else:
            op_addr = repr(op_addr)
        op_val = repr(op_addr)
    elif 'READ' in oper:
        # Check the AST for taint.
        m = mmio_read_re.match(repr(op_val))
        if m:
            op_val = int(m.group(1), 0)
            if svd_device:
                periph, reg = lookup_by_addr(svd_device, op_val)
                if periph and reg:
                    periph_info = "%s->%s (%s, %s)" % (periph.name, reg.name, periph.description, reg.description)
                    # oh come on, who did this...
                    periph_info = periph_info.replace("\n", "")
            op_val = hex(op_val)
            op_addr = op_val
        else:
            op_val = repr(op_val)
        if op_label:
            op_val = op_label
        if not isinstance(op_addr, str) and not isinstance(op_addr, int) and not op_addr.concrete:
            op_addr = "<symbolic>"
        else:
            op_addr = repr(op_addr)
    try:
        lck.acquire()
        mmio_log.write(", ".join([hex(func_addr), hex(inst_addr), oper, op_addr, op_val, periph_info]) + "\n")
        mmio_log.flush()
    finally:
        lck.release()


def is_messy_expr(expr):
    d = expr.depth
    if expr.op == "Reverse" or expr.op == "Extract":
        # Hack: angr adds extra reverses/extracts we don't care about
        d -= 1
    return d >= 6 #WhySix


def is_pointer(p, addr):
    # TODO: FIXME: Some day when type recovery exists, switch this for something better
    if isinstance(addr, int):
        if addr > 0x1f000000: # Chosen because that's the lowest non-code region in ARM Cortex-M
            return p.loader.find_object_containing(addr) is not None
    return False


def is_mmio_address(addr):
    for s, e in MMIO_RANGES:
        if s <= addr < e:
            return True
    return False


def is_stack_address(state, addr):
    sp = state.solver.eval(state.regs.sp)
    if abs( sp - addr) < 0x100000:
        return True
    return False


# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")

all_mmio_addrs = set()

def mmio_detector(opts, p, f_addr, init_state, n_funcs=0, tot_funcs=0):

    write_instrs = set()
    read_instrs = set()
    dma_write_instrs = set()
    dma_read_instrs = set()
    timed_out = threading.Event()
    errored = threading.Event()

    ##
    ## Taint Policy
    ##

    def smartcall_policy(s):
        arg_regs = get_function_arg_names(p, s.addr)
        for regname in arg_regs:
            try:
                regval = s.reg_concrete(regname)
                # If an MMIO address itself is an argument, do it
                if is_mmio_addr(regval):
                    #l.warning("Function %#08x takes MMIO pointer %#08x in register %s" % (s.addr, regval, regname))
                    return True
                # If a global pointing to MMIO is an argument, also do it
                elif s.project.loader.find_object_containing(regval) and s.mem[regval].uint32_t.resolved.concrete:
                    memval = s.mem[regval].uint32_t.concrete
                    if is_mmio_addr(memval):
                        #l.warning("Function %#08x takes MMIO global pointer %#08x in register %s" % (s.addr, regval, regname))
                        return True
                elif regval in opts.io_pointers:
                    # We manually identified this pointer.  Trace it.
                    return True
            except SimValueError:
                pass
        #l.warning("Skipping call to %#08x, no MMIO here" % (s.addr))
        return False

    def mem_read_before(state):
        ip = state.addr
        # If we are dereferencing a value read from MMIO, that's probably a DMA read.
        if is_tainted(state.inspect.mem_read_address, state=state) and ip not in dma_read_instrs:
            l.info("[%#08x] Suspected DMA read found at %#08x, addr %s" % (f_addr, ip, repr(state.inspect.mem_read_address)))
            dma_read_instrs.add(ip)
            write_mmio_log(state, 'DMA_READ', f_addr, ip, state.inspect.mem_read_address)
            return
        addr_sym = state.inspect.mem_read_address
        addr = state.solver.eval(addr_sym)
        if not isinstance(addr_sym, int) and not addr_sym.concrete:
            # Not even a concrete address? Man, we're screwed.
            return
        # If we are reading from an MMIO address, this is of course an MMIO read, and we should
        # taint the value for later
        if is_mmio_address(addr):
            all_mmio_addrs.add(addr)
            # EDG: We don't care about the read until we see what we do with the data!
            apply_taint(state, addr, "mmio_read_%s" % hex(addr), bits=32)

    def mem_write_before(state):
        ip = state.addr
        expr = state.inspect.mem_write_expr
        if not state.inspect.mem_write_address.concrete:
            if is_tainted(expr, state=state) and ip not in read_instrs:
                # We are writing MMIO data to memory somewhere
                # Is it a function argument or not?
                addr = state.inspect.mem_write_address
                function_arg_taints = get_function_arg_names(p, state.addr)
                dst = expr
                for tb in function_arg_taints:
                    if tb in str(addr): #HACK: Ugh...
                        # We're writing to a function argument!
                        dst = tb
                        break
                l.info("[%#08x] Wrote MMIO data to symbolic address at %#08x: %s" % (f_addr, ip, repr(expr)))
                write_mmio_log(state, 'MMIO_READ', f_addr, ip, addr, expr, dst)
                read_instrs.add(ip)

        else:
            # The address target is constant
            addr = state.solver.eval(state.inspect.mem_write_address)
            if is_mmio_address(addr):
                # We arre writing to an MMIO address
                all_mmio_addrs.add(addr)
                if not is_messy_expr(expr) and not is_tainted(expr, state=state):
                    if not expr.concrete and ip not in write_instrs:
                        src = "<symbolic>"
                        # Where are we writing?
                        function_arg_taints = get_function_arg_names(p, state.addr)
                        for tb in function_arg_taints:

                            if tb in str(expr):  # HACK: Ugh...
                                src = tb
                        l.info("[%#08x] MMIO write found to %#08x at %#08x: %s" % (f_addr, addr, ip, repr(expr)))
                        write_instrs.add(ip) # Only alert the same instr once
                        write_mmio_log(state, 'MMIO_WRITE', f_addr, ip, state.inspect.mem_write_address, src)
                    else:
                        if ip not in dma_write_instrs:
                            # we're writing a concrete value.  Most of the time we want to ignore this
                            # as usually this means flags and stuff.
                            # However....
                            concrete_expr = state.solver.eval(expr)
                            if is_pointer(p, concrete_expr) and ip not in dma_write_instrs:
                                l.info("[%#08x] Possible DMA write found to %#08x at %#08x: %s" % (f_addr, addr, ip, hex(concrete_expr)))
                                dma_write_instrs.add(ip)  # Only alert the same instr once
                                write_mmio_log(state, 'DMA_WRITE', f_addr, ip, state.inspect.mem_write_address, op_val=hex(concrete_expr))
            else:
                # Writing data to a constant address that is NOT MMIO
                if is_tainted(expr, state=state):
                    # We're writing MMIO data to a constant memory address
                    if not is_stack_address(state, addr):
                        if not is_messy_expr(expr) and not ip in read_instrs:
                            l.info("[%#08x] Wrote MMIO data to %#08x at %#08x: %s" % (f_addr, addr, ip, repr(expr)))
                            write_mmio_log(state, 'MMIO_READ', f_addr, ip, hex(addr), repr(expr))
                            read_instrs.add(ip)

    def exit_before(state):
        # Intuition: If we're returning some MMIO data out of the function, it's probably interesting
        ip = state.addr
        #target = state.solver.eval(state.inspect.exit_target)

        try:
            ret_val_expr = get_return_value(p, f_addr, state)
        except RuntimeError:
            # We can't tell if we're void or not, be conservative
            ret_val_expr = state.regs.r0
        if ret_val_expr is None:
            # Void function!
            return
        jk = state.inspect.exit_jumpkind
        if jk == 'Ijk_Ret':
            if is_tainted(ret_val_expr, state=state) and not is_messy_expr(ret_val_expr):
                if ip not in read_instrs:
                    l.info("[%#08x] Returning MMIO data to %#08x" % (f_addr, ip))
                    read_instrs.add(ip)
                    write_mmio_log(state, 'MMIO_READ', f_addr, ip, "RET", repr(ret_val_expr))

    l.warning("Analyzing %#08x (%d / %d)" % (f_addr, n_funcs, tot_funcs))

    # prepare the state
    if init_state is None:
        state = p.factory.call_state(f_addr)
    else:
        state = p.factory.call_state(f_addr, base_state=init_state)

    state.solver._solver.timeout = (120 * 1000) # Set internal z3 timer to 2 minutes for performance
    simgr = p.factory.simgr(state)
    tt = TaintTracker(interfunction_level=opts.ifl, precise_argument_check=False, taint_deref_values=False,
                      smart_call=True, should_follow_call=smartcall_policy)
    # NOTE: We set taint_deref_values to false here; if we dereference a tainted value (e.g., DMA) we do not
    # care what derefs happen based on this data (e.g., accessing a structure in DMA) We already found the DMA buffer!
    # NOTE 2: We disable smartcalls due to the fact that our taint is memory-based and not function-based.
    # We cannnot know where taint will come from, so skipping anything is bad!
    # NOTE 3: ....except we use the above Smartcall Policy to solve this problem while reducing the
    # code we need to excute!
    ed = ExplosionDetector(threshold=400)
    simgr.use_technique(ed)

    def timeout():
        l.warning("TIMEOUT %#08x" % f_addr)
        tt.stop()
        timed_out.set()
        ed.timed_out.set()

    # Hook up the taint tracker
    tt.add_callback(mem_read_before, 'mem_read', angr.BP_BEFORE)
    tt.add_callback(mem_write_before, 'mem_write', angr.BP_BEFORE)
    tt.add_callback(exit_before, 'exit', angr.BP_BEFORE)

    # Intuition: IO functions that use loops will do the IO 
    # regardless of how many times they loop!
    # Therefore, we explore loops only once.
    ls = LoopSeer(p.cfg, bound=1, limit_concrete_loops=False)

    tt._N = 9001 # Disable Nilo's not-quite-LoopSeer
    simgr.use_technique(ls)
    simgr.use_technique(tt)

    # Optimization: keep only `num_states` states alive.
    # Try not to run out of memory too fast.
    dfs = DFS(num_states=opts.dfs_states)
    simgr.use_technique(dfs)

    # Optimization: If we deadend, who cares, get that stuff out of memory ASAP
    simgr.use_technique(TheDeadendinator())

    # Start the timer
    timer = Timer(opts.timeout, timeout)
    #while simgr.active[0].addr != 0x8009e19:
    #    simgr.step()
    #import ipdb; ipdb.set_trace()
    timer.start()
    
    try:
        simgr.run()
    except:
        l.exception("Error analyzing %#08x" % f_addr)
        import ipdb; ipdb.set_trace()
        errored.set()
    timer.cancel()
    gc.collect()
    return f_addr, read_instrs, write_instrs, dma_read_instrs, dma_write_instrs, all_mmio_addrs, timed_out.is_set(), errored.is_set()


def setup_logging(p):
    global l
    global mmio_log
    logging.basicConfig()
    l = logging.getLogger("MMIOFinder")
    if opts.debug:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)
    logfile = logging.FileHandler(os.path.basename(p.filename) + ".log")
    formater = logging.Formatter(logging.BASIC_FORMAT)
    logfile.setFormatter(formater)
    l.addHandler(logfile)
    shut_up("TaintTracking")
    shut_up("angr.knowledge_plugins.key_definitions.dataset")
    shut_up("angr.analyses.loopfinder")
    shut_up("angr.analyses.reaching_definitions.engine_vex.SimEngineRDVEX")
    shut_up("angr.engines.vex.engine")
    shut_up("angr.engines.successors")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.analyses.init_finder.SimEngineInitFinderVEX")
    shut_up("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX")
    shut_up("angr.analyses.cfg.cfg_fast")
    shut_up("angr.analyses.xrefs.SimEngineXRefsVEX")
    shut_up("cle.backends.elf.elf")
    mmio_log = open(os.path.basename(p.filename) + ".out", 'w')


def is_mmio_addr(addr):
    for start, end in MMIO_RANGES:
        if start <= addr < end:
            return True
    return False


def find_candidates(p, known_io_addrs):
    """
    Find candidates for MMIOFinder.  A function is considered a candidate if it reads, writes, or accesses a pointer to MMIO.
    We then use this set of functions as start locations for symexec, to figure out how these pointers are used.

    Optimization 1: We use the new Propagator and XRefs to find more of these.
    Optimization 2: We use InitializationsFinder to look for places where these are passed around in globals, but concretely
    initialized to a specific value.

    :param p:
    :return:
    """
    #init_state = get_fullest_init_state(p)
    init_state = get_magical_init_state(p, p.cfg)
    candidates = set()
    bad_functions = list()
    for func in p.kb.functions:
        f = p.kb.functions[func]
        refs = p.kb.xrefs.get_xrefs_by_ins_addr_region(func, func + f.size)

        # Hook out assert-fails
        if len(cfg.model.get_any_node(func).predecessors) > 1 and not p.kb.functions[func].returning:
            bad_functions.append(func)
            p.hook(func, Deadend())

        for ref in refs:
            if not isinstance(ref.dst, int):
                continue
            # If the ref is to MMIO, this function is a candidate
            if is_mmio_addr(ref.dst):
                l.warning("Function %#08x accesses MMIO %#08x" % (func, ref.dst))
                candidates.add(func)
            # If the ref is to a global that's been initialized as MMIO, this function is a candidate
            elif init_state.mem[ref.dst].int32_t.resolved.concrete:
                global_data = init_state.mem[ref.dst].int32_t.concrete
                if is_mmio_addr(global_data):
                    l.warning("Function %#08x accesses global MMIO pointer %#08x with value %#08x"
                              % (func, ref.dst, global_data))
                    candidates.add(func)
            elif ref.dst in known_io_addrs:
                l.warning("Function %#08x accesses manually-identified global MMIO pointer %#08x"
                          % (func, ref.dst))
                candidates.add(func)
    return list(candidates), init_state

def mem_profile():
    px = psutil.Process()
    mx = px.memory_info()
    l.warning("### MEMORY STATS ###")
    l.warning("Master (PID %d): %s (%2f%%)" % (px.pid, (mx.rss / (1024 ** 3)), px.memory_percent()))
    for ch in px.children(recursive=True):
        mx = ch.memory_info()
        l.warning("\tChild (PID %d): %02f GB (%2f%%)" % (px.pid, (mx.rss / (1024 ** 3)), ch.memory_percent()))


def dump_candidates(candidates):
    with open("mmio_candidates", 'w+') as f:
        for c in candidates:
            f.write(hex(candidate) + '\n')


def load_candidates():
    with open('mmio_candidates', 'r') as f:
        candidates = []
        for line in f.read().splitlines():
            if line.strip():
                candidates.append(auto_int(line.strip()))
    return candidates


if __name__ == '__main__':
    global svd_device
    opts = parse_opts()
    fname = opts.binary 

    # If we know the chip, load our chip info
    if opts.model:
        svd_device = find_device(opts.model)
        if not svd_device:
            print("ERROR: CPU model %s not found" % opts.model)
            sys.exit(1)
    else:
        svd_device = None
    p = None
    if opts.resume:
        try:
            with open(opts.resume, 'rb') as f:
                p = pickle.load(f)
                cfg = p.cfg
        except FileNotFoundError:
            l.critical("Resume file not found, rebuilding...")
    if not p:
        if opts.logix:
            p, cfg = auto_analyze()  # For now
            # TODO: Remove the need for this from the PLC
            # (this hooks out the stack check)
            p.hook(0x375c04, Deadend())
            p.hook(0x0034C65C, Deadend())
            p.hook(0x0034CA38, Deadend())
        else:
            if opts.auto:
                import autoblob

                p = load_it(opts.binary, mmio_regions=opts.mmio_region)
            else:
                p = load_it(opts.binary, opts.arch, opts.base_addr, opts.entry_point, opts.mmio_region)
            cfg = cfg_it(p)
        print("Saving project...")
        with open(os.path.basename(p.filename) + ".angrproject", 'wb') as f:
            p.cfg = cfg
            pickle.dump(p, f)
    setup_logging(p)
    candidates, init_state = find_candidates(p, opts.io_pointers)
    l.warning("Static phase: Found %d candidate IO functions" % len(candidates))
    if opts.dump_candidates:
        dump_candidates()
        sys.exit(0)
    total_mmio_reads = set()
    total_mmio_writes = set()
    total_dma_reads = set()
    total_dma_writes = set()
    total_mmio_addrs = set()
    total_timed_out = 0
    total_errored = 0
    #import ipdb; ipdb.set_trace()
    if opts.single:
        N = 1
        func_addrs = [opts.single]
    else:
        N = len(candidates)
        func_addrs = candidates
    if opts.nprocs == 1:
        # Disable thread-pool
        for n, f in enumerate(func_addrs):
            res = mmio_detector(opts, p, f, init_state, n, N)
            f_addr, read_instrs, write_instrs, dma_read_instrs, dma_write_instrs, all_mmio_addrs, timed_out, errored = res
            total_mmio_addrs |= all_mmio_addrs
            total_mmio_reads |= read_instrs
            total_mmio_writes |= write_instrs
            total_dma_reads |= dma_read_instrs
            total_dma_writes |= dma_write_instrs
            if errored:
                total_errored += 1
            if timed_out:
                total_timed_out += 1
    else:
            mypool = Pool(processes=opts.nprocs)
            results = [mypool.apply_async(mmio_detector, (opts, p, f, init_state, n, N)) for n, f in enumerate(func_addrs)]
            for r in results:
                f_addr, read_instrs, write_instrs, dma_read_instrs, dma_write_instrs, all_mmio_addrs, timed_out, errored = r.get()
                total_mmio_addrs |= read_instrs
                total_mmio_writes |= write_instrs
                total_dma_reads |= dma_read_instrs
                total_dma_writes |= dma_write_instrs
                if errored:
                    total_errored += 1
                if timed_out:
                    total_timed_out += 1
                gc.collect()
                if opts.profile:
                    mem_profile()
    l.critical("FINAL RESULTS:")
    l.critical("Total Functions: %d" % len(p.kb.functions))
    l.critical("Total candidate functions: %d" % len(candidates))
    l.critical("Total MMIO ops detected: %d" % len(total_mmio_addrs))
    l.critical("  Total useful MMIO ops: %d" % (len(total_mmio_reads) + len(total_mmio_writes) +
                                                len(total_dma_reads) + len(total_dma_writes)))
    l.critical("Total useful MMIO reads detected: %s " % len(total_mmio_reads))
    l.critical("Total useful MMIO writes detected: %s " % len(total_mmio_writes))
    l.critical("Total DMA reads detected: %s " % len(total_dma_reads))
    l.critical("Total DMA writes detected: %s " % len(total_dma_writes))
    l.critical("Total timeouts: %d " % total_timed_out)
    l.critical("Total errored: %d " % total_errored)
