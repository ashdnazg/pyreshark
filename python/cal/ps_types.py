from ctypes import *
from ws_types import *

PSdissect_func = CFUNCTYPE(None, POINTER(WStvbuff), c_size_t, c_size_t, POINTER(c_int), c_size_t)

class PSdissection_node(Structure):
    _fields_ = [("func", PSdissect_func),
                ("params", c_size_t)]

class PSpy_dissector(Structure):
    _fields_ = [("dissection_chain", POINTER(POINTER(PSdissection_node))),
                ("length", c_int),
                ("name", c_char_p)]
                