'''
@summary: Declares the counterpatrts to the structures defined in pyreshark.h
'''

from ctypes import CFUNCTYPE, POINTER, Structure, c_int, c_void_p, c_char_p
from ws_types import WStvbuff, WSproto_node, WSpacket_info

class PStvbuff_and_tree(Structure):
    _fields_ = [("tvb", POINTER(WStvbuff)),
                ("tree", POINTER(WSproto_node))]

PSdissect_func = CFUNCTYPE(None, POINTER(PStvbuff_and_tree), POINTER(WSpacket_info), POINTER(c_int), c_void_p)

class PSdissection_node(Structure):
    _fields_ = [("func", c_void_p),
                ("params", c_void_p)]

class PSpy_dissector(Structure):
    _fields_ = [("dissection_chain", POINTER(POINTER(PSdissection_node))),
                ("length", c_int),
                ("name", c_char_p)]
                