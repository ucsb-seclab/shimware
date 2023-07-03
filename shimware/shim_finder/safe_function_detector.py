from ..loaders.generic import load_it, cfg_it
import optparse
import angr
import struct
import re
import pyvex
import logging
from angr.state_plugins.sim_action import SimActionData
from pyvex.lifting.gym.arm_spotter import ARMSpotter
from multiprocessing.pool import ThreadPool as Pool
import sys
import argparse


log = logging.getLogger("safe_functions")


N = 2


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

def is_pointless_function(p, f_addr, bad_loops, step_limit=9000):
    # Step 0: Find the function
    try:
        f = p.kb.functions[f_addr]
        cs = p.factory.call_state(f_addr)
    except:
        log.exception("Error finding function info for %#08x" % f_addr)
        return f_addr, False
    lol = [cs.options.add(x) for x in angr.options.refs]
    sm = p.factory.simgr(cs)
    sm.save_unconstrained = True
    # Criteria 1: Filter short junk
    if len(list(f.block_addrs)) < 2:
        log.debug("Function %#08x is too short" % f_addr)
        return f_addr, False
    try:
        vr = p.analyses.VariableRecoveryFast(f)
        vfm = vr.variable_manager.function_managers[f.addr]

    except:
        log.exception("Error performing variable recovery for %#08x" % f_addr)
        return f_addr, False
    i = 0
    while len(sm.active) > 0:
        # Criteria 1: We can't tell, because the function is either too long, or stuck in a loop
        if i > step_limit:
            log.debug("Step limit reached in %#08x" % f_addr)
            return f_addr, False
        if len(sm.active) > 1:
            # Criteria 2: The function branches, and therefore the input or state of the program determines its behavior.
            log.debug("%#08x is useful, branches at %s" % (f_addr, repr([hex(s.addr) for s in sm.active])))
            return f_addr, False
        i += 1
        #log.debug("Executed block %d of %#08x" % (i, f_addr))
        
        s = sm.active[0]
        cur_ip = s.se.eval(s.ip)
        if cur_ip in bad_loops:
            # Criteria 3: There's definitely an infinite loop, the function does not return. We can't replace this.
            log.debug("%#08x hits an infinite loop at %#08x" % (f_addr, cur_ip))
            return f_addr, False
        if "Ijk_Call" in s.history.jumpkinds:
            # Criteria 4: The thing calls a function. therefore we can't replace it safely.
            log.debug("%#08x is useful, calls a function at %#08x" % (f_addr, cur_ip))
            return f_addr, False
        for a in s.state.actions:
            # Criteria 5: If it writes to memory that's outside of the local stack, it can't 
            if isinstance(a, angr.state_plugins.sim_action.SimActionData):
                if a.type == 'mem' and a.action == 'write':
                    varis = vfm.find_variables_by_insn(a.ins_addr, 'memory')
                    if not varis:
                        log.debug("%#08x is useful, writes memory at %#08x" % (f_addr, a.ins_addr))
                        return f_addr, False
        sm.step()
    if len(sm.unconstrained) > 0:
        # We went unconstrained.  Check memory before returning
        s = sm.unconstrained[0]
        for a in s.state.actions:
        # Criteria 5a: If it writes to memory that's outside of the local stack, it can't 
            if isinstance(a, angr.state_plugins.sim_action.SimActionData):
                if a.type == 'mem' and a.action == 'write':
                    varis = vfm.find_variables_by_insn(a.ins_addr, 'memory')
                    if not varis:
                        log.debug("%#08x is useful, writes memory at %#08x" % (f_addr, a.ins_addr))
                        return f_addr, False
    # TODO: Check return values.
    log.critical("%#08x IS USELESS" % f_addr)
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

def setup_logging():
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.WARNING)
    log.setLevel(logging.CRITICAL)
    log.critical("Loading binary")

if __name__ == '__main__':
    opts = parse_opts()
    fname = opts.binary
    setup_logging()
    p = load_it(fname, opts.arch, opts.base_addr, opts.entry_point)
    if not opts.no_cfg and not opts.single:
        cfg = cfg_it(p)
    log.critical("Starting safe function analysis")
    bad_loops = fast_infinite_loop_finder(p)
    pointless_funcs = []
    func_addrs = p.kb.functions.keys()
    if opts.single:
        is_pointless_function(p, opts.single, bad_loops)
    elif opts.nprocs == 1:
        for f in func_addrs:
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
