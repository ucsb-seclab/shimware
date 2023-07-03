import angr
from cle.backends import NamedRegion
import logging
import claripy
from angr.analyses.cfg import CFGUtils
from ..shim_finder_ng.util import get_function_arg_names
l = logging.getLogger("shimware.loaders.generic")

def load_it(fname, arch=None, base_addr=None, entry_point=None, mmio_regions=[]):
    if not arch and not base_addr and not entry_point:
        p = angr.Project(fname, page_size=1)

    else:
        p = angr.Project(fname, main_opts={'base_addr': base_addr, 'arch': arch, 'backend': 'blob', 'entry_point': entry_point})
    region_count = 0
    for start, end in mmio_regions:
        region = NamedRegion("mmio%d" % region_count, start, end)
        p.loader.dynamic_load(region)
    # TODO: Stack locatio
    return p


def cfg_it(p):
    cfg = p.analyses.CFGFast(function_prologues=True,
                             resolve_indirect_jumps=True,
                             normalize=True,
                             force_complete_scan=False,
                             show_progressbar=True,
                             cross_references=True,
                             detect_tail_calls=True)
    _ = p.analyses.CompleteCallingConventions(recover_variables=True, force=True)
    return cfg


def fill_uninitialized_unconstrained(p, state):
    # Avoid zeroing the BSS so we can reason about the content
    for sec in p.loader.main_object.sections:
        if sec.only_contains_uninitialized_data:
            for addr in range(sec.min_addr, sec.max_addr, 4):
                sym = claripy.BVS(sec.name + "_" + hex(addr), 32)
                state.memory.store(addr, sym)


def get_concrete_arg_sets(p: angr.Project, cfg, f: int, props: dict):
    arg_sets = set()
    arg_regs = get_function_arg_names(p, f)
    call_sites = cfg.model.get_any_node(f).predecessors
    #import ipdb; ipdb.set_trace()
    # If a function is called a lot, it probably does not do initialization
    if len(call_sites) > 6: #WhySix
        return arg_sets
    if not call_sites:
        # assume the default CC
        return [{},]
    for site in call_sites:
        if site.function_address not in props:
            l.error("Uh oh, traversed %#08x before %#08x" % (f, site.function_address))
            continue
            #import ipdb; ipdb.set_trace()
        f_props = props[site.function_address]
        args = []
        for arg in arg_regs:
            try:
                args.append(f_props.get_register_at_block(site.addr, arg))
            except KeyError:
                args.append(None)
        # Compress equivalent arg sets
        arg_sets.add(tuple(args))
    # FUTURE WORK: Do something special if the args collide
    # For now we assume that each context does not conflict
    # This is closed-captioned for the hearing impaired.
    out = []
    for arg_set in arg_sets:
        args = {name: arg for name, arg in zip(arg_regs, arg_set)}
        out.append(args)
    return out


def get_magical_init_state(p, cfg):
    """
    The infamous fullest-est-er init state, or, an inter-functional version of the
    original.
    """
    failed = 0
    success = 0
    res = None
    state = p.factory.blank_state()
    fill_uninitialized_unconstrained(p, state)
    overlay = state.memory
    props = dict()
    # Traverse funcs in topo order, so that later inits override previous ones
    sorted_funcs = CFGUtils.quasi_topological_sort_nodes(p.kb.functions.callgraph)
    for f in sorted_funcs:
        func = p.kb.functions[f]
        # Ignore externs and junk
        if func.is_simprocedure or func.is_plt:
            continue
        try:
            arg_sets = get_concrete_arg_sets(p, cfg, f, props)
            # Now, for each callsite,
            # Run the Propagator
            for args in arg_sets:
                prop = p.analyses.Propagator(func=func, func_graph=func.graph, base_state=state,
                                             initial_registers=args)
                props[f] = prop
                res = p.analyses.InitializationFinder(func=p.kb.functions[f], replacements=prop.replacements,
                                                      overlay=overlay, pointers_only=True)
            success += 1
        except:
            l.exception("FAILED on %#08x" % f)
            failed += 1
    l.critical("Success: %d, Failed: %d" % (success, failed))
    return state


def get_fullest_init_state(p):
    """
    Use the InitializationsFinder to get the "fullest init state"

    This is the state that, theoretically speaking, has all the constant "initialization" stuff done, but computed entirely statically

    CAUTION: This function is so unsound it requires closed-captioning.

    :param p:
    :param cfg:
    :return:
    """
    failed = 0
    success = 0
    res = None
    state = p.factory.blank_state()
    fill_uninitialized_unconstrained(p, state)
    overlay = state.memory
    # Traverse funcs in topo order, so that later inits override previous ones
    sorted_funcs = CFGUtils.quasi_topological_sort_nodes(p.kb.functions.callgraph)
    for f in sorted_funcs:
        func = p.kb.functions[f]
        # Ignore externs and junk
        if func.is_simprocedure or func.is_plt:
            continue
        try:
            res = p.analyses.InitializationFinder(func=p.kb.functions[f], overlay=overlay)
            success += 1
        except:
            l.exception("FAILED on %#08x" % f)
            failed += 1
    l.critical("Success: %d, Failed: %d" % (success, failed))
    return state
