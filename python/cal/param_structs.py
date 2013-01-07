'''
@dummary: Declares all the ctypes Param Strcutures. See param_structs.h for the C versions.
'''

from ctypes import POINTER, Structure, c_int, c_uint, c_char_p
from ws_types import WSproto_node, WSproto_tree

class PSadd_tree_item_params(Structure):
    _fields_ = [("p_hf_index", POINTER(c_int)),
                ("length", c_int),
                ("encoding", c_uint),
                ("out_item", POINTER(WSproto_node))]
                
class PSadd_text_item_params(Structure):
    _fields_ = [("p_hf_index", POINTER(c_int)),
                ("length", c_int),
                ("text", c_char_p),
                ("out_item", POINTER(WSproto_node))]
                
class PSpush_tree_params(Structure):
    _fields_ = [("parent", POINTER(POINTER(WSproto_node))),
                ("p_index", POINTER(c_int)),
                ("p_start_offset", POINTER(c_int)),
                ("out_tree", POINTER(WSproto_tree))]
                
class PSpop_tree_params(Structure):
    _fields_ = [("p_start_offset", POINTER(c_int)),]
    
class PSadvance_offset_params(Structure):
    _fields_ = [("length", c_int),
                ("encoding", c_int)]
                
class PSset_column_text_params(Structure):
    _fields_ = [("col_id", c_int),
                ("text", c_char_p)]
                
class PScall_next_dissector_params(Structure):
    _fields_ = [("name", POINTER(c_char_p)),
                ("default_name", c_char_p)]