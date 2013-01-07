'''
@summary: Holds the main class of the C Abstraction Layer.
'''

from ctypes import POINTER, pointer, addressof, CDLL
from ps_types import PSdissection_node, PSpy_dissector

PSLIBNAME = "pyreshark"
WSLIBNAME = "libwireshark"

class CAL(object):
    
    def __init__(self):
        self.pslib = CDLL(PSLIBNAME)
        self.wslib = CDLL(WSLIBNAME)
       
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
        
        return pointer(PSdissection_node(self.pslib.get_pointer(func), p_params))
        
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