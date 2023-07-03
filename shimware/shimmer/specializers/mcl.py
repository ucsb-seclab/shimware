import os
import struct
import logging
from .specializer import Specializer, register_specializer


l = logging.getLogger(__name__)

class MCLSpecializer(Specializer):
    name = "MCL"

    def default_base(self):
        return 0x08000000

    def default_scratch(self):
        return 0x0800085C


register_specializer(MCLSpecializer)
