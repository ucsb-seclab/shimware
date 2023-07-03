from angr.exploration_techniques import ExplorationTechnique
from .dynamic_taint.taint_tracking import TaintTracker
from .dynamic_taint.dfs import DFS
from angr.exploration_techniques import LengthLimiter, LoopSeer
from threading import Event, Timer
import logging
import angr

l = logging.getLogger('util')
l.setLevel('INFO')


def get_return_value(p, f_addr, state):
    """
    Helper to get the return value of a function.
    """
    f = p.kb.functions[f_addr]
    cfg = p.cfg
    # If the function has no callsites, we can't get the return value
    if not cfg.model.get_predecessors(cfg.model.get_node(f.addr)):
        raise RuntimeError("Function %#08x has no callsites, cannot get return value" % f.addr)
    # Get the real calling convention
    res = p.analyses.CallingConvention(f, cfg, analyze_callsites=True)
    if not res.cc:
        raise RuntimeError("Cannot recover CC for %#08x" % f_addr)
    if res.cc.ret_val:
        return res.cc.ret_val.get_value(state)
    return None

def get_function_arg_names(p, addr):
    # TODO: Support memory args.  Do people do that still? On x86 yes, but....
    try:
        f = p.kb.functions.floor_func(addr)
        if f and f.calling_convention:
            arg_names = [a.reg_name for a in f.calling_convention.args]
            return arg_names
    except:
        pass
    finally:
        return angr.calling_conventions.DEFAULT_CC[p.arch.name].ARG_REGS


class ExplosionDetector(ExplorationTechnique):
    def __init__(self, stashes=('active', 'deferred', 'errored', 'cut'), threshold=100):
        super(ExplosionDetector, self).__init__()
        self._stashes = stashes
        self._threshold = threshold
        self.timed_out = Event()

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        total = 0
        if len(simgr.unconstrained) > 0:
            l.debug("Nuking unconstrained")
            #import IPython; IPython.embed()
            simgr.move(from_stash='unconstrained', to_stash='_Drop', filter_func=lambda _: True)
            #for st in self._stashes:
            #    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)
            #    return simgr
        if self.timed_out.is_set():
            l.critical("Timed out, %d states: %s" % (total, str(simgr)))
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)
        for st in self._stashes:
            if hasattr(simgr, st):
                total += len(getattr(simgr, st))

        if total >= self._threshold:
            l.critical("State explosion detected, over %d states: %s" % (total, str(simgr)))
            for st in self._stashes:
                if hasattr(simgr, st):
                    simgr.move(from_stash=st, to_stash='_Drop', filter_func=lambda _: True)
        return simgr


def the_funpacker(p, cfg, entry):
    l.critical("Attempting to unpack blob data...")
    # Step 0: Find the function
    try:
        f = p.kb.functions[entry]
        cs = p.factory.call_state(entry)
    except:
        l.exception("Error finding function info for %#08x" % entry)
        return None
    if not f.endpoints:
        print("Uh oh! The entry point function has no endpoints? Ask Eric.")
    endpoint = f.endpoints[0].addr
    lol = [cs.options.add(x) for x in angr.options.refs]
    sm = p.factory.simgr(cs)

    def smartcall_policy(*args, **kwargs):
        return False
    tt = TaintTracker(interfunction_level=0, precise_argument_check=False, taint_deref_values=False,
                      smart_call=True, should_follow_call=smartcall_policy)
    tt._N = 9999999
    sm.use_technique(tt)

    # Don't step too much
    sm.use_technique(LengthLimiter(max_length=9001))
    ed = ExplosionDetector(threshold=69)
    sm.use_technique(ed)
    ls = angr.exploration_techniques.LoopSeer(cfg, bound=1, limit_concrete_loops=False)
    # import ipdb; ipdb.set_trace()
    sm.use_technique(DFS())

    def timeout():
        l.critical("TIMEOUT %#08x" % f_addr)
        ed.timed_out.set()

    timer = Timer(69, timeout)
    timer.start()
    try:
        sm.explore(find=endpoint)
    except:
        pass
    finally:
        timer.cancel()
    # ... some time later ...
    if hasattr(sm, 'found') and sm.found:
        return sm.found[0]
    else:
        l.critical("Wow, we couldn't find the end of the entry point!")
        return None
