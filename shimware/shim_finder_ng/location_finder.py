from ..loaders.generic import load_it, cfg_it, get_fullest_init_state
from ..loaders.ab_controllogix import auto_analyze
import angr
import pickle
pickle._HAVE_PICKLE_BUFFER = False
from angr.procedures.libc.abort import abort
import struct
import re
import logging
from angr.state_plugins.sim_action import SimActionData
from multiprocessing.pool import ThreadPool as Pool
import argparse
import os
from threading import Lock, Event
from .util import ExplosionDetector, get_return_value, get_function_arg_names

l = logging.getLogger("LocationFinder")


def auto_int(x):
    return int(x, 0)


def parse_opts():
    global MMIO_RANGES
    o = argparse.ArgumentParser()
    o.add_argument("--debug", action='store_true')
    o.add_argument("--single", type=auto_int)
    o.add_argument("--nprocs", type=auto_int, default=1)
    o.add_argument("--timeout", type=auto_int, default=600)
    o.add_argument("--no_cfg", action='store_true')
    o.add_argument('-M', '--mmio-region', action='append', nargs=2, type=auto_int)
    o.add_argument("--logix", action='store_true')
    o.add_argument("--auto", action='store_true')
    o.add_argument("--ifl", type=int, default=0)
    o.add_argument("--dfs-states", type=auto_int, default=1)
    o.add_argument("--base_addr", type=auto_int, default=0x100000)
    o.add_argument("--entry_point", type=auto_int, default=0x100000)
    o.add_argument("--resume")
    o.add_argument("--arch", default="ARMEL")
    o.add_argument("binary")
    opts = o.parse_args()
    if opts.mmio_region:
        MMIO_RANGES = opts.mmio_region
    else:
        MMIO_RANGES = [(0x10000000, 0x20000000),
                       (0x40000000, 0x50000000),
                       (0x8000000, 0x9000000)]
    return opts

log_lck = Lock()
log_file = open("location_log", 'w')


def write_location_log(addr, length):

    log_lck.acquire()
    try:
        log_file.write("%#08x, %d\n" % (addr, length))
        log_file.flush()
    except:
        pass
    finally:
        log_lck.release()


def is_pointless_function(p, f_addr, bad_loops, step_limit=9000):
    # Step 0: Find the function
    try:
        f = p.kb.functions[f_addr]
        cs = p.factory.call_state(f_addr)
    except:
        l.exception("Error finding function info for %#08x" % f_addr)
        return f_addr, False
    if f_addr == 0x08066f31 or f_addr == 0x0801305d:
        return f_addr, False
    lol = [cs.options.add(x) for x in angr.options.refs]
    sm = p.factory.simgr(cs)
    sm.save_unconstrained = True
    try:
        vfm = p.kb.variables[f.addr]
    except:
        l.critical("Error performing variable recovery for %#08x" % f_addr)
        return f_addr, False
    i = 0
    while len(sm.active) > 0:
        # Criteria 1: We can't tell, because the function is either too long, or stuck in a loop
        if i > step_limit:
            l.debug("Step limit reached in %#08x" % f_addr)
            return f_addr, False
        if len(sm.active) + len(sm.unconstrained) > 1:
            # Criteria 2: The function branches, and therefore the input or state of the program determines its behavior.
            l.debug("%#08x is useful, branches at %s" % (f_addr, repr([hex(s.addr) for s in sm.active])))
            return f_addr, False
        i += 1

        s = sm.active[0]
        cur_ip = s.se.eval(s.ip)
        if cur_ip in bad_loops:
            # Criteria 3: There's definitely an infinite loop, the function does not return. We can't replace this.
            l.debug("%#08x hits an infinite loop at %#08x" % (f_addr, cur_ip))
            return f_addr, False
        if "Ijk_Call" in s.history.jumpkinds:
            # Criteria 4: The thing calls a function. therefore we can't replace it safely.
            l.debug("%#08x is useful, calls a function at %#08x" % (f_addr, cur_ip))
            return f_addr, False
        for a in s.history.actions:
            # Criteria 5: If it writes to memory that's outside of the local stack, it can't 
            if isinstance(a, angr.state_plugins.sim_action.SimActionData):
                if a.type == 'mem' and a.action == 'write':
                    varis = vfm.find_variables_by_insn(a.ins_addr, 'memory')
                    if not varis:
                        l.debug("%#08x is useful, writes memory at %#08x" % (f_addr, a.ins_addr))
                        return f_addr, False
        sm.step()
    if len(sm.unconstrained) > 0:
        # We went unconstrained.  Check memory before returning
        s = sm.unconstrained[0]
        for a in s.history.actions:
        # Criteria 5a: If it writes to memory that's outside of the local stack, it can't 
            if isinstance(a, angr.state_plugins.sim_action.SimActionData):
                if a.type == 'mem' and a.action == 'write':
                    varis = vfm.find_variables_by_insn(a.ins_addr, 'memory')
                    if not varis:
                        l.debug("%#08x is useful, writes memory at %#08x" % (f_addr, a.ins_addr))
                        return f_addr, False

    # If we can't get to the end without going unconstrained, we can't guarantee anything:
    if len(sm.deadended) == 0:
        return f_addr, False
    try:
        retval = get_return_value(p, f_addr, sm.deadended[0])
        if retval is not None:
            # The function returns something
            if not retval.concrete:
                # THe function returns
                # some function of its input, or a memory location
                # we can't attest. Be conservative
                return f_addr, False
    except:
        # Fallback to the original behavior if we can't determine voidness
        pass
    l.critical("%#08x IS USELESS" % f_addr)
    write_location_log(f_addr, f.size)
    return f_addr, True


def fast_infinite_loop_finder(p):
    la = p.analyses.LoopFinder()
    bad_loops = []
    for loop in la.loops:
        if not loop.break_edges:
            for node in loop.graph.nodes():
                if not isinstance(node, angr.codenode.BlockNode):
                    continue
                bad_loops.append(node.addr)
    return bad_loops


# Shortcut to make angr's noisy logging less noisy
def shut_up(thing):
    lol = logging.getLogger(thing)
    lol.setLevel("CRITICAL")


def setup_logging():
    global l
    logging.basicConfig()
    l = logging.getLogger("LocationFinder")
    if opts.debug:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)
    logfile = logging.FileHandler("./mmio_finder.log")
    l.addHandler(logfile)
    shut_up("TaintTracking")
    shut_up("angr.analyses.disassembly")
    shut_up("angr.engines.vex.engine")
    shut_up("angr.engines.successors")
    shut_up("angr.state_plugins.symbolic_memory")
    shut_up("pyvex.lifting.gym.arm_spotter")
    shut_up("angr.analyses.init_finder.SimEngineInitFinderVEX")
    shut_up("angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX")
    shut_up("angr.analyses.cfg.cfg_fast")
    shut_up("angr.analyses.xrefs.SimEngineXRefsVEX")
    shut_up("cle.backends.elf.elf")


def is_mmio_addr(addr):
    for start, end in MMIO_RANGES:
        if start <= addr < end:
            return True
    return False


def has_spotted_instructions(p, f_addr):
    """
    Determine if any of the instructions we had to use a Spotter to nop out are here

    We can't guarantee correct execution for those, so we ignore these functions

    """
    bad = ['ldc', 'stc', 'cdp', 'mrc', 'mcr']
    f = p.kb.functions[f_addr]
    try:
        d = p.analyses.Disassembly(f).render()
    except:
        l.exception("Could not disassemble %#08x" % (f_addr))
        return True # Be conservative
    for s in bad:
        if s in d:
            l.critical("%#08x contains spotted instructions, skipping" % (f_addr))
            return True
    return False

def static_phase(p, cfg):
    deadends = set()
    io_funcs = set() # IO Funcs are not useless
    short_funcs = set()
    spotted_funcs = set()
    init_state = get_fullest_init_state(p)
    for func in p.kb.functions.keys():
        # Find all the deadend functions.
        # You could probably remove these and replace them with
        # while(1)
        f = p.kb.functions[func]
        # Ignore functions that are too short
        # Criteria 1: Filter short junk
        if len(cfg.model.get_any_node(func).predecessors) > 6 and not p.kb.functions[func].returning:
            deadends.add(func)
            p.hook(func, abort())
            continue
        elif len(list(f.block_addrs)) < 2:
            l.debug("Function %#08x is too short" % func)
            short_funcs.add(func)
            continue
        elif has_spotted_instructions(p, func):
            spotted_funcs.add(func)
            continue
        # Hook out assert-fails
        else:
            # MMIO funcs can't be useless
            refs = p.kb.xrefs.get_xrefs_by_ins_addr_region(func, func + f.size)
            for ref in refs:
                if not isinstance(ref.dst, int):
                    continue
                # If the ref is to MMIO, this function is a candidate
                if is_mmio_addr(ref.dst):
                    l.warning("Function %#08x accesses MMIO %#08x" % (func, ref.dst))
                    io_funcs.add(func)
                # If the ref is to a global that's been initialized as MMIO, this function is a candidate
                if init_state.mem[ref.dst].int32_t.resolved.concrete:
                    global_data = init_state.mem[ref.dst].int32_t.concrete
                    if is_mmio_addr(global_data):
                        l.warning("Function %#08x accesses global MMIO pointer %#08x with value %#08x"
                                  % (func, ref.dst, global_data))
                        io_funcs.add(func)

    # We don't need to analyze IO Funcs
    dynamic_candidates = set(p.kb.functions.keys()).difference(io_funcs)
    dynamic_candidates = dynamic_candidates.difference(deadends)
    dynamic_candidates = dynamic_candidates.difference(short_funcs)
    dynamic_candidates = dynamic_candidates.difference(spotted_funcs)
    l.critical("STATIC PHASE: Identified %d functions" % len(p.kb.functions.keys()))
    l.critical("STATIC PHASE: Ignoring %d short functions" % len(short_funcs))
    l.critical("STATIC PHASE: Ignoring %d functions with spotted instructions" % len(spotted_funcs))
    l.critical("STATIC PHASE: Remove %d deadend functions" % len(deadends))
    l.critical("STATIC PHASE: Ignoring %d possible IO functions" % len(io_funcs))
    l.critical("STATIC PHASE: Found %d candidate functions" % len(dynamic_candidates))
    return dynamic_candidates, deadends


def empty_region_finder(p):
    """
    Finds empty regions in the main object of an angr project.

    A region is considered empty IF:
    1) It contains only one byte value (e.g., all zeros, all FFs, etc)
    2) It has no static cross-references to it
    3) It is not contained in any function.
    """
    l.critical("Beginning empty region finder")
    min_addr = p.loader.main_object.min_addr
    max_addr = p.loader.main_object.max_addr
    start = min_addr
    start_word = None
    largest_region_start = None
    largest_region_size = 0
    word_size = p.arch.bits // 8 # I feel ashamed...
    while start < max_addr - word_size:
        start_word = p.loader.memory.unpack_word(start, word_size)
        # Maybe TODO: Filter in good start_words like 00 or ff
        region_end = start
        for i in range(start, max_addr, word_size):
            cur_word = p.loader.memory.unpack_word(i, word_size)
            if cur_word != start_word:
                region_end = i
                break
        else:
            region_end = max_addr
        # If the region is large
        if region_end - start > largest_region_size:
            # ...and nothing's pointing at it
            refs = p.kb.xrefs.get_xrefs_by_ins_addr_region(start, region_end)
            if len(refs) == 0:
                # We have a winner!
                largest_region_size = region_end - start
                largest_region_start = start
        start = region_end
    l.critical("Largest free region: %#08x (size %#08x" % (largest_region_start, largest_region_size))
    write_location_log(largest_region_start, largest_region_size)

if __name__ == '__main__':
    opts = parse_opts()
    fname = opts.binary
    setup_logging()
    p = None
    cfg = None
    if opts.resume:
        try:
            with open(opts.resume, 'rb') as f:
                p = pickle.load(f)
                cfg = p.cfg
        except FileNotFoundError:
            l.warning("Couldn't find resume file, recreating...")
        except:
            p = None
            l.exception("Loading project failed, rebuilding...")
    if not p:
        if opts.logix:
            p, cfg = auto_analyze()  # For now
            # TODO: Remove the need for this from the PLC
            # (this hooks out the stack check)
            p.hook(0x375c04, abort())
            p.hook(0x0034C65C, abort())
            p.hook(0x0034CA38, abort())
        else:
            if opts.auto:
                import autoblob

                p = load_it(opts.binary, mmio_regions=opts.mmio_region)
            else:
                p = load_it(opts.binary, opts.arch, opts.base_addr, opts.entry_point, opts.mmio_region)
            cfg = cfg_it(p)
        l.critical("Saving project...")
        with open(os.path.basename(p.filename) + ".angrproject", 'wb') as f:
            p.cfg = cfg
            pickle.dump(p, f)

    func_addrs, deadends = static_phase(p, cfg)
    empty_regions = empty_region_finder(p)

    l.critical("Starting safe function analysis")
    bad_loops = fast_infinite_loop_finder(p)
    pointless_funcs = []
    if opts.single:
        is_pointless_function(p, opts.single, bad_loops)
    elif opts.nprocs == 1:
        for x, f in enumerate(func_addrs):
            l.critical("Analyzing function %#08x (%d / %d)" % (f, x, len(func_addrs)))
            if is_pointless_function(p, f, bad_loops):
                pointless_funcs.append(f)
    else:
        with open("safe_funcs", 'w') as funcs_file:
            mypool = Pool(processes=opts.nprocs)
            results = [mypool.apply_async(is_pointless_function, (p, f, bad_loops)) for f in func_addrs]
            for r in results:
                f, is_pointless = r.get()
                if is_pointless:
                    pointless_funcs.append(f)
                    funcs_file.write(hex(f) + "\n")
