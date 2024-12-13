from m5.objects.ClockedObject import ClockedObject
from m5.params import *


class SecureMemory(ClockedObject):
    type = "SecureMemory"
    cxx_header = "bootcamp/insepctor_gadget/secure_memory.hh"
    cxx_class = "gem5::SecureMemory"
    cpu_side_port = ResponsePort("ResponsePort to receive requests from CPU side.")
    mem_side_port = RequestPort("RequestPort to send received requests to memory side.")
    inspection_buffer_entries = Param.Int("Number of entries in the inspection buffer.")
    response_buffer_entries = Param.Int("Number of entries in the response buffer.")
