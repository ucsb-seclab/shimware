import logging
import angr
import pyvex
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.analyses.reaching_definitions.atoms import Register, MemoryLocation
from angr.analyses.reaching_definitions.dataset import DataSet
from angr.analyses.reaching_definitions.undefined import Undefined

l = logging.getLogger(name=__name__)


class SimTaintEngineRDVEX(SimEngineRDVEX):  # pylint:disable=abstract-method
    def __init__(self, project, current_local_call_depth, maximum_local_call_depth, function_handler=None):
        assert current_local_call_depth is not None
        assert maximum_local_call_depth is not None
        SimEngineRDVEX.__init__(self, project, current_local_call_depth, maximum_local_call_depth, function_handler)

    def _test_taint(self, value):
        if 'Undefined' in str(type(value)):
            return False
        if 'tuple' in str(type(value)):
            if 'taint' in value[1]:
                return True
            else:
                return False
        # arm_IO policy
        if value >= 0x40000000 and value <= 0x50000000:
            return True
        # custom arm_IO policy
        #elif value >= 0x8000000 and value <= 0x9000000:
        #    return True
        else:
            return False

    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        data = self._expr(stmt.data)

        '''
        data_m = set()
        data_isTainted = False
        for d in data:
            # taint policy
            if 'Undefined' in str(type(d)):
                continue
            if 'tuple' in str(type(d)):
                d = d[0]
            if (d >= 0x40000000 and d <= 0x50000000):
                data_isTainted = True
                data_m.add((d, "taint"))
        data = data_m
        '''

        addr_isUndef = False
        for a in addr:
            if type(a) is Undefined:
                addr_isUndef = True
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
            else:
                if any(type(d) is Undefined for d in data):
                    l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                memloc = MemoryLocation(a, size)
                # different addresses are not killed by a subsequent iteration, because kill only removes entries
                # with same index and same size
                self.state.kill_and_add_definition(memloc, self._codeloc(), data)

        # IO WRITE policy: check whether a tainted value is used at undefined address
        '''
        if (data_isTainted and addr_isUndef):
            print('GOTCHA! IO WRITE!')
        '''


    def _handle_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard.data == {True}:
            self._handle_Store(stmt)
        elif guard.data == {False}:
            pass
        else:
            # guard.data == {True, False}
            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8

            # get current data
            load_end = stmt.end
            load_ty = self.tyenv.lookup(stmt.data.tmp)

            load_addr = stmt.addr
            load_expr = pyvex.IRExpr.Load(load_end, load_ty, load_addr)
            data_old, taint = self._handle_Load(load_expr)
            # get new data
            data_new = self._expr(stmt.data)

            # merge old and new data
            data_new.update(data_old)

            for a in addr:
                if type(a) is Undefined:
                    l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)
                else:
                    if any(type(d) is Undefined for d in data_new):
                        l.info('Data to write at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)

                    memloc = MemoryLocation(a, size)

                    # different addresses are not killed by a subsequent iteration, because kill only removes entries
                    # with same index and same size

                    self.state.kill_and_add_definition(memloc, self._codeloc(), data_new, taint)

    def _handle_Put(self, stmt):
        reg_offset = stmt.offset
        size = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size)
        data = self._expr(stmt.data)
        taint = False
        if 'tuple' in str(type(data)):
            taint = data[1]
            data = data[0]

        if any(type(d) is Undefined for d in data):
            l.info('Data to write into register <%s> with offset %d undefined, ins_addr = %#x.',
                   self.arch.register_names[reg_offset], reg_offset, self.ins_addr)

        self.state.kill_and_add_definition(reg, self._codeloc(), data, taint)

    def _handle_Load(self, expr):
        addr = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) // 8
        bits = expr.result_size(self.tyenv)
        data = set()

        for a in addr:
            if isinstance(a, int):
                current_defs = self.state.memory_definitions.get_objects_by_offset(a)
                if current_defs:
                    for current_def in current_defs:
                        data.update(current_def.data)
                    if any(type(d) is Undefined for d in data):
                        l.info('Memory at address %#x undefined, ins_addr = %#x.', a, self.ins_addr)
                else:
                    try:
                        data.add(self.state.loader.memory.unpack_word(a, size=size))
                    except KeyError:
                        pass

                # FIXME: _add_memory_use() iterates over the same loop
                self.state.add_use(MemoryLocation(a, size), self._codeloc())
            else:
                l.info('Memory address undefined, ins_addr = %#x.', self.ins_addr)

        if len(data) == 0:
            data.add(Undefined(bits))

        taint = False
        for a in addr:
            if self._test_taint(a):
                taint = True
                break
                #memloc = MemoryLocation(a, size)
                #self.state.kill_and_add_definition(memloc, self._codeloc(), DataSet(data, expr.result_size(self.tyenv)), True)

        return DataSet(data, expr.result_size(self.tyenv)), taint
