'''
@summary: Declares the counterpatrts to the structures defined in pyreshark.h
'''
# ps_types.py
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

from ctypes import CFUNCTYPE, POINTER, Structure, c_int, c_void_p, c_char_p
from ws_types import WStvbuff, WSproto_node, WSpacket_info

class PStvbuff_and_tree(Structure):
    _fields_ = [("tvb", POINTER(WStvbuff)),
                ("tree", POINTER(WSproto_node))]

PSdissect_func = CFUNCTYPE(None, POINTER(PStvbuff_and_tree), POINTER(WSpacket_info), POINTER(c_int), c_void_p)
PS_DISSECT_FUNC_ARGS = [POINTER(PStvbuff_and_tree), c_void_p, POINTER(c_int), c_void_p]
class PSdissection_node(Structure):
    _fields_ = [("func", c_void_p),
                ("params", c_void_p)]

class PSpy_dissector(Structure):
    _fields_ = [("dissection_chain", POINTER(POINTER(PSdissection_node))),
                ("length", c_int),
                ("name", c_char_p)]
