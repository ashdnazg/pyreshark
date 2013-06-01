'''
@summary: Declares all the ctypes Param Strcutures. See param_structs.h for the C versions.
'''
# param_structs.py
#
# Pyreshark Plugin for Wireshark. (http://code.google.com/p/pyreshark)
#
# Copyright (c) 2013 by Eshed Shaham.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

from ctypes import POINTER, Structure, c_int, c_uint, c_char_p, c_ubyte
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
                ("encoding", c_int),
                ("flags", c_int),]
                
class PSset_column_text_params(Structure):
    _fields_ = [("col_id", c_int),
                ("text", c_char_p)]
                
class PScall_next_dissector_params(Structure):
    _fields_ = [("name", POINTER(c_char_p)),
                ("length", POINTER(c_int)),        #-1 for all remaining bytes. 
                ("default_name", c_char_p),
                ("default_length", c_int)]
                
class PSpush_tvb_params(Structure):
    _fields_ = [("name", c_char_p),
                ("data", c_char_p),  #Originally c_ubyte
                ("length", c_int),
                ("p_old_offset", POINTER(c_int))]
                
class PSpop_tvb_params(Structure):
    _fields_ = [("p_old_offset", POINTER(c_int))]