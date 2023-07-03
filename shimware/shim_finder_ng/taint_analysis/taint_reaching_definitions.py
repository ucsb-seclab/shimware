import logging
from collections import defaultdict

from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses import register_analysis
from angr.analyses.forward_analysis import ForwardAnalysis, FunctionGraphVisitor
from angr.analyses.reaching_definitions.reaching_definitions import LiveDefinitions, ReachingDefinitionAnalysis
from angr.analyses.reaching_definitions.atoms import Register, MemoryLocation, Tmp, Parameter
from angr.calling_conventions import SimRegArg, SimStackArg

from .taint_engine_vex import SimTaintEngineRDVEX
from .taint_definition import TaintDefinition

l = logging.getLogger(name=__name__)

class TaintLiveDefinitions(LiveDefinitions):
    def __init__(self, arch, loader, track_tmps=False, analysis=None, init_func=False, cc=None, func_addr=None):
        super(TaintLiveDefinitions, self).__init__(arch, loader, track_tmps, analysis, init_func, cc, func_addr)

    def copy(self):
        rd = TaintLiveDefinitions(
            self.arch,
            self.loader,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            init_func=False,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd._dead_virgin_definitions = self._dead_virgin_definitions.copy()

        return rd

    def _init_func(self, cc, func_addr):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = TaintDefinition(sp, None, DataSet(self.arch.initial_sp, self.arch.bits))
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)
        if self.arch.name.startswith('MIPS'):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9 = Register(self.arch.registers['t9'][0],self.arch.bytes)
            t9_def = TaintDefinition(t9, None, DataSet(func_addr,self.arch.bits))
            self.register_definitions.set_object(t9_def.offset,t9_def,t9_def.size)

        if cc is not None:
            for arg in cc.args:
                # initialize register parameters
                if type(arg) is SimRegArg:
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = TaintDefinition(reg, None, DataSet(Parameter(reg), self.arch.bits))
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif type(arg) is SimStackArg:
                    ml = MemoryLocation(self.arch.initial_sp + arg.stack_offset, self.arch.bytes)
                    sp_offset = SpOffset(arg.size * 8, arg.stack_offset)
                    ml_def = TaintDefinition(ml, None, DataSet(Parameter(sp_offset), self.arch.bits))
                    self.memory_definitions.set_object(ml.addr, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture depended initialization
        if self.arch.name.lower().find('ppc64') > -1:
            rtoc_value = self.loader.main_object.ppc64_initial_rtoc
            if rtoc_value:
                offset, size = self.arch.registers['rtoc']
                rtoc = Register(offset, size)
                rtoc_def = TaintDefinition(rtoc, None, DataSet(rtoc_value, self.arch.bits))
                self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = TaintDefinition(t9, None, DataSet(func_addr, self.arch.bits))
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def kill_and_add_definition(self, atom, code_loc, data, dummy=False, taint = False):
        if type(atom) is Register:
            self._kill_and_add_register_definition(atom, code_loc, data, dummy, taint)
        elif type(atom) is MemoryLocation:
            self._kill_and_add_memory_definition(atom, code_loc, data, dummy, taint)
        elif type(atom) is Tmp:
            self._add_tmp_definition(atom, code_loc)
        else:
            raise NotImplementedError()

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom, code_loc, data, dummy=False, taint=False):

        # FIXME: check correctness
        current_defs = self.register_definitions.get_objects_by_offset(atom.reg_offset)
        if current_defs:
            uses = set()
            for current_def in current_defs:
                uses |= self.register_uses.get_uses(current_def)
            if not uses:
                self._dead_virgin_definitions |= current_defs

        definition = TaintDefinition(atom, code_loc, data, taint)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)

    def _kill_and_add_memory_definition(self, atom, code_loc, data, dummy=False, taint=False):
        definition = TaintDefinition(atom, code_loc, data, taint)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)

class TaintReachingDefinitionAnalysis(ReachingDefinitionAnalysis):  # pylint:disable=abstract-method
    def __init__(self, func=None, block=None, func_graph=None, max_iterations=3, track_tmps=False,
                 observation_points=None, init_state=None, init_func=False, cc=None, function_handler=None,
                 current_local_call_depth=1, maximum_local_call_depth=5, observe_all=False):

        if func is not None:
            if block is not None:
                raise ValueError('You cannot specify both "func" and "block".')
            # traversing a function
            graph_visitor = FunctionGraphVisitor(func, func_graph)
        elif block is not None:
            # traversing a block
            graph_visitor = SingleNodeGraphVisitor(block)
        else:
            raise ValueError('Unsupported analysis target.')

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=graph_visitor)

        self.instructions = set()

        self._track_tmps = track_tmps
        self._max_iterations = max_iterations
        self._function = func
        self._block = block
        self._observation_points = observation_points
        self._init_state = init_state
        self._function_handler = function_handler
        self._current_local_call_depth = current_local_call_depth
        self._maximum_local_call_depth = maximum_local_call_depth
        self._observe_all = observe_all

        if self._init_state is not None:
            self._init_state = self._init_state.copy()
            self._init_state.analysis = self

        # ignore initialization parameters if a block was passed
        if self._function is not None:
            self._init_func = init_func
            self._cc = cc
            self._func_addr = func.addr
        else:
            self._init_func = False
            self._cc = None
            self._func_addr = None

        # sanity check
        if self._observation_points and any(not type(op) is tuple for op in self._observation_points):
            raise ValueError('"observation_points" must be tuples.')

        if not self._observation_points:
            l.warning('No observation point is specified. '
                      'You cannot get any analysis result from performing the analysis.'
                      )

        self._node_iterations = defaultdict(int)
        self._states = {}

        self._engine_vex = SimTaintEngineRDVEX(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)
        self._engine_ail = SimEngineRDAIL(self.project, self._current_local_call_depth, self._maximum_local_call_depth,
                                          self._function_handler)

        self.observed_results = {}

        self._analyze()

    def _initial_abstract_state(self, node):
        if self._init_state is not None:
            return self._init_state
        else:
            return TaintLiveDefinitions(self.project.arch, self.project.loader, track_tmps=self._track_tmps,
                                   analysis=self, init_func=self._init_func, cc=self._cc, func_addr=self._func_addr)
register_analysis(TaintReachingDefinitionAnalysis, "TaintReachingDefinitions")