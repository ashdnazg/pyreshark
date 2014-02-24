'''
@summary: Holds the main class of the C Abstraction Layer.
'''
# c_abstraction_layer.py
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

from ctypes import POINTER, pointer, addressof, CDLL, c_void_p, cast, c_char_p
from ps_types import PSdissection_node, PSpy_dissector
from ws_types import WS_CREATE_DISSECTOR_HANDLE_ARGS, WS_CREATE_DISSECTOR_HANDLE_RETURN, WS_DISSECTOR_ADD_UINT_ARGS, WS_DISSECTOR_ADD_STRING_ARGS
import platform

PSLIBNAME_DICT = {"Windows" : "pyreshark.dll", "Linux" : "pyreshark.so"}
WSLIBNAME_DICT = {"Windows" : "libwireshark.dll", "Linux" : "libwireshark.so"}

class CAL(object):
    
    def __init__(self):
        system = platform.system()
        self.pslib = CDLL(PSLIBNAME_DICT[system])
        self.wslib = CDLL(WSLIBNAME_DICT[system])
       	self.wslib.create_dissector_handle.argtypes = WS_CREATE_DISSECTOR_HANDLE_ARGS
        self.wslib.create_dissector_handle.restype = WS_CREATE_DISSECTOR_HANDLE_RETURN
        self.wslib.dissector_add_uint.argtypes = WS_DISSECTOR_ADD_UINT_ARGS
        self.wslib.dissector_add_string.argtypes = WS_DISSECTOR_ADD_STRING_ARGS
        
    def create_dissection_node(self, func, params):
        '''
        @summary: Creates a new dissection node.
        @param func: A dissectuin function (either dissect_func_t or PSdissect_func).
        @param params: The appropriate param's structure for the func.
        @return: A pointer to a new PSdissection_node.
        '''
        if params is None:
            p_params = None
        else:
            p_params = addressof(params)
        return pointer(PSdissection_node(c_void_p.from_address(addressof(func)).value, p_params))
        
    def create_chain(self, node_list):
        '''
        @summary: Creates the dissection chain for a single dissector.
        @param node_list: A list of tuples of the form (func, params).
        @return: A pointer to an array of pointers to PSdissection_noode structs created from node_list.
        '''
        dissection_node_list = [self.create_dissection_node(node, params) for node, params in node_list]
        array_type = POINTER(PSdissection_node) * len(dissection_node_list)
        node_array = array_type(*dissection_node_list)
        return pointer(node_array[0])
        
    def register_protocols(self, protocols):
        '''
        @summary: Registers all python protocols.
        @param protocols: A list of Protocol objects.
        '''
        dissectors_list = []
        for proto in protocols:
            proto.register(self)
            node_list = proto.get_node_list()
            chain = self.create_chain(node_list)
            dissectors_list.append(PSpy_dissector(chain, len(node_list), proto._short_name))
        array_type = POINTER(PSpy_dissector) * len(dissectors_list)
        self._dissectors_array = array_type(*[pointer(d) for d in dissectors_list])
        self.pslib.register_dissectors_array(len(self._dissectors_array), pointer(self._dissectors_array[0]))

    def error_message(self, message):
        self._message = c_char_p(message)
        self.wslib.report_failure(self._message)
