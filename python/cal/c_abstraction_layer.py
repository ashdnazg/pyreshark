from ctypes import *
from ws_types import *
from ps_types import *

PSLIBNAME = "pyreshark"
WSLIBNAME = "libwireshark"

DISSECT_FUNCTIONS = []

class CAL(object):
    
    def __init__(self):
        self._pslib = CDLL(PSLIBNAME)
        self._wslib = CDLL(WSLIBNAME)
        self._dissect_func_dict = {}
        
        for function in DISSECT_FUNCTIONS:
            try:
                self._dissect_func_dict[function] = getattr(self._pslib, function)
            except:
                print "Warning: Function %s doesn't seem to be in the DLL" % function
        
        self._c_print_tvb = PSdissect_func(self._print_tvb)
        
        dummy_node = PSdissection_node(self._c_print_tvb, 0)
        
        dummy_dissector = PSpy_dissector(pointer(pointer(dummy_node)), 1, "pyreshark")
        self._dissector_array = pointer(pointer(dummy_dissector))
        self._pslib.register_dissectors_array(1, self._dissector_array)
    
    def _print_tvb(self, p_tvb, p_pinfo, p_tree, p_offset, params):
        for field in WStvbuff._fields_:
            print "%s: %s" % (field[0], getattr(p_tvb.contents, field[0]))
        print "\n"
        
    