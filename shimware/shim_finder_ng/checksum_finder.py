#!/usr/bin/env python3

import angr
import argparse
from ..loaders.generic import load_it, cfg_it, get_fullest_init_state
from ..loaders.ab_controllogix import auto_analyze
from .dynamic_taint.dfs import DFS
from .dynamic_taint.deadendinator import TheDeadendinator
from angr.exploration_techniques import ExplorationTechnique, LengthLimiter, LoopSeer
import logging
import pickle
from angr import options as o
from collections import defaultdict
from threading import Lock
import os
from threading import Event, Timer
import gc
from .dynamic_taint.taint_tracking import TaintTracker
from angr.errors import SimValueError
from angr.procedures.libc.abort import abort as Deadend
from .util import ExplosionDetector


def auto_int(x):
	return int(x, 0)


log_lck = Lock()
log_file = open("selfcheck_log", 'w')


def write_checksum_log(f_addr, addr, n):

	log_lck.acquire()
	try:
		log_file.write("%#08x, %#08x, %d\n" % (f_addr, addr, n))
		log_file.flush()
	except:
		pass
	finally:
		log_lck.release()


def loopfinder_filter(p, f_addr, reads, writes):
	"""
	Encodes the intuition that a self-check will read many locations (the whole binary)
	and write only few of them (the check value)

	Loops that read many locations, and also write many locations are probably copy loops.

	"""
	fns = [p.kb.functions.floor_func(x) for x in reads]
	fns += [p.kb.functions.floor_func(x) for x in writes]
	lf = p.analyses.LoopFinder(fns)
	selfchecks = set()
	for read in reads:
		found_it = False
		read_loop = None
		# Find what loop this address belongs to
		for loop in lf.loops:
			for bl in loop.body_nodes:
				if bl.addr <= read < bl.addr + bl.size:
					read_loop = loop
					found_it = True
					break
			if found_it:
				break
		found_it_again = False
		if read_loop:
			for write in writes:
				for bl in read_loop.body_nodes:
					if bl.addr <= write < bl.addr + bl.size:
						# Copy loop!
						l.debug("Found a copy loop at %#08x" % read)
						found_it_again = True
						break
				if found_it_again:
					break
			else:
				# This loop reads, but not writes
				selfchecks.add(read)
	return selfchecks

def checksum_finder(p, f_addr, opts, step_limit=1000, N=20, func_num=1, func_total=1):
	l.critical("Checking %#08x (%d / %d)" % (f_addr, func_num, func_total))

	program_addrs = defaultdict(lambda: set())

	# Breakpoint for memory reads
	def mem_read_before(state):
		target = state.inspect.mem_read_address
		# We have to know where it's coming from
		if target.concrete:
			target_addr = state.solver.eval_one(target)
			# Is this a self-reference?
			if state.project.loader.main_object.contains_addr(target_addr):
				# We got one!
				program_addrs[state.addr].add(target_addr)

	# Track writes, so we can find and ignore copy loops
	write_addrs = defaultdict(lambda: set())

	# Breakpoint for memory reads
	def mem_write_after(state):
		target = state.inspect.mem_write_address
		# We have to know where it's coming from
		if target.concrete:
			target_addr = state.solver.eval_one(target)
			write_addrs[state.addr].add(target_addr)

	def smartcall_policy(s):
		arg_regs = ['r0', 'r1', 'r2', 'r3']
		for regname in arg_regs:
			try:
				regval = s.reg_concrete(regname)
				# If a self-reference is an argument, do it
				if is_self_addr(s.project, regval):
					#l.warning("Function %#08x takes MMIO pointer %#08x in register %s" % (s.addr, regval, regname))
					return True
				# If a global pointing to a self-reference is an argument, also do it
				elif s.project.loader.find_object_containing(regval) and s.mem[regval].uint32_t.resolved.concrete:
					memval = s.mem[regval].uint32_t.concrete
					if is_self_addr(s.project, memval):
						return True
				else:
					pass
					#l.warning("Not taking call to %#08x" % s.addr)
			except SimValueError:
				pass


	# Step 0: Find the function
	try:
		cs = p.factory.call_state(f_addr)
	except:
		l.exception("Error finding function info for %#08x" % f_addr)
		return f_addr, False

	cs.options.update(o.refs)
	cs.inspect.b('mem_read', angr.BP_BEFORE, action=mem_read_before)
	cs.inspect.b('mem_write', angr.BP_AFTER, action=mem_write_after)

	sm = p.factory.simgr(cs, veritesting=False)

	# Borrow the taint tracker for its smart call feature
	tt = TaintTracker(interfunction_level=99, precise_argument_check=False, taint_deref_values=False,
					  smart_call=True, should_follow_call=smartcall_policy)
	tt._N = N
	sm.use_technique(tt)

	# Don't step too much
	sm.use_technique(LengthLimiter(max_length=step_limit))

	# Shorten loops
	sm.use_technique(LoopSeer(cfg=cfg, functions=[f_addr], bound=N))

	# Self-checks are unlikely to state-explode, due to their inherent concreteness
	ed = ExplosionDetector()
	sm.use_technique(ed)

	# Use DFS to keep the memory manageable
	sm.use_technique(DFS())

	# Prune deadended paths
	sm.use_technique(TheDeadendinator())

	#import ipdb; ipdb.set_trace()

	def timeout():
		l.critical("TIMEOUT %#08x" % f_addr)
		ed.timed_out.set()

	timer = Timer(opts.timeout, timeout)
	timer.start()

	# ...aaaaand go!!

	try:
		sm.run()
	except:
		pass
	finally:
		timer.cancel()
		gc.collect()

	# ... some time later ...
	loop_read_addresses = set()
	loop_write_addresses = set()

	# If we see >= N addresses from the same location that are all self-references
	# it's probably a self-check!
	for i in program_addrs:
		if not any([is_self_addr(p, z) for z in program_addrs[i]]):
			# False-positive! The binary is doing random loopy stuff on itself inside of the
			# candidate self-check.  For exapmle, the MCL calls memmove() from within check_signature()
			continue
		if len(program_addrs[i]) >= N:
			loop_read_addresses.add(i)
	for i in write_addrs:
		if len(write_addrs[i]) >= N:
			loop_write_addresses.add(i)

	# Finally, if we are reading, then writing, this is probably some copy loop.
	checksum_addresses = loopfinder_filter(p, f_addr, loop_read_addresses, loop_write_addresses)
	for check in checksum_addresses:
		l.critical("Self-check found at %#08x, %d hits" % (check, len(program_addrs[check])))
		write_checksum_log(f_addr, check, len(program_addrs[check]))
	return f_addr, checksum_addresses


def shut_up(thing):
	lol = logging.getLogger(thing)
	lol.setLevel("CRITICAL")


def setup_logging(opts):
	global l
	logging.basicConfig()
	l = logging.getLogger("ChecksumFinder")
	if opts.debug:
		l.setLevel(logging.DEBUG)
	else:
		l.setLevel(logging.INFO)
	logfile = logging.FileHandler("./checksum_finder.log")
	l.addHandler(logfile)
	shut_up("TaintTracking")
	#shut_up("angr.engines.vex.engine")
	shut_up("angr.engines.successors")
	shut_up("angr.state_plugins.symbolic_memory")
	shut_up("pyvex.lifting.gym.arm_spotter")


def parse_opts():
	o = argparse.ArgumentParser()
	o.add_argument("--debug", action='store_true')
	o.add_argument("--logix", action='store_true')
	o.add_argument("--auto", action='store_true')
	o.add_argument("--nprocs", type=auto_int, default=1)
	o.add_argument('-M', '--mmio-region', action='append', nargs=2, type=auto_int)
	o.add_argument("--timeout", type=auto_int, default=600)
	o.add_argument("--no_cfg", action='store_true')
	o.add_argument("--ifl", type=int, default=0)
	o.add_argument("--dfs-states", type=auto_int, default=1)
	o.add_argument("--base_addr", type=auto_int, default=0x100000)
	o.add_argument("--entry_point", type=auto_int, default=0x100000)
	o.add_argument("--single", type=auto_int)
	o.add_argument("--resume")
	o.add_argument("--arch", default="ARMEL")
	o.add_argument("binary")
	opts = o.parse_args()
	return opts


# Firmware will be aligned to a flash page.
def is_self_addr(p, addr):
	return addr % 0x400 == 0 and p.loader.main_object.contains_addr(addr)


def static_phase(p, cfg):
	"""
	Statically speaking, a self-check function should do some of:
	1) do math
	2) dominate some big amount of the program
	3) Reference the beginning of the firmware
	or
	4) talk to some crypto hardware

	"""

	bad_functions = []
	candidates = set()

	# TODO: Do we need the full init state?
	init_state = get_fullest_init_state(p)
	for func in p.kb.functions.keys():
		f = p.kb.functions[func]
		# Hook out assert-fails
		if len(cfg.model.get_any_node(func).predecessors) > 1 and not p.kb.functions[func].returning:
			bad_functions.append(func)
			p.hook(func, Deadend())

		# Look for refs to the function
		refs = p.kb.xrefs.get_xrefs_by_ins_addr_region(func, func + f.size)
		for ref in refs:
			if not isinstance(ref.dst, int):
				continue
			# If the ref is a self-reference, this function is a candidate
			if is_self_addr(p, ref.dst):
				l.warning("Function %#08x accesses the binary at %#08x" % (func, ref.dst))
				candidates.add(func)
			# If the ref is to a global that's been initialized as a self-reference, this function is a candidate
			if init_state.mem[ref.dst].int32_t.resolved.concrete:
				global_data = init_state.mem[ref.dst].int32_t.concrete
				if is_self_addr(p, global_data):
					l.warning("Function %#08x accesses global binary pointer %#08x with value %#08x"
							  % (func, ref.dst, global_data))
					candidates.add(func)

	# FUTURE WORK: Add thing to look for functions that dictate whether the program boots
	l.critical("STATIC PHASE: Identified %d functions" % len(p.kb.functions.keys()))
	l.critical("STATIC PHASE: Remove %d deadend functions" % len(bad_functions))
	l.critical("STATIC PHASE: Found %d candidate self-checks" % len(candidates))
	return candidates


if __name__ == "__main__":
	opts = parse_opts()
	setup_logging(opts)
	p = None
	cfg = None
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
		l.critical("Saving project...")
		with open(os.path.basename(p.filename) + ".angrproject", 'wb') as f:
			p.cfg = cfg
			pickle.dump(p, f)
	func_addrs = static_phase(p, cfg)
	if opts.single:
		print(checksum_finder(p, opts.single, opts))
	else:
		num_funcs = len(func_addrs)
		for x, f in enumerate(func_addrs):
			checksum_finder(p, f, opts, func_num=x, func_total=num_funcs)
