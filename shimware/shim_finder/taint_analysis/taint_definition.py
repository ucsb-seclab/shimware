from angr.analyses.reaching_definitions.definition import Definition

class TaintDefinition(Definition):
    def __init__(self, atom, codeloc, data, taint = False):
        super(TaintDefinition, self).__init__(atom, codeloc, data)
        self.taint = taint
