'''
@summary: Main module, doesn't hold much logic.
Don't import this, as it relies on sys being already imported in the C code
'''
import os.path
from glob import glob

PYRESHARK_DIR = sys.path[-1]
PROTOCOLS_DIR = os.path.join(PYRESHARK_DIR, "protocols")


# The following is to handle the situation where the user doesn't have enough privileges to open the logs.
try:
    sys.stdout = open("%s\\out.log" % sys.path[-1],"wb")
    sys.stderr = open("%s\\err.log" % sys.path[-1],"wb")
except:
    pass

sys.path.append(PROTOCOLS_DIR)
    
import cal

class PyreShark(object):
    '''
    @summary: A class holding the main routines for pyreshark
    '''
    def __init__(self):
        '''
        @summary: Initializes the CAL, instantiates the python plugins and registers them.
        '''
        self._protocols = []
        self._cal = cal.CAL()
        protocol_files = glob("%s\\*.py" % (PROTOCOLS_DIR,))
        
        for p_file in protocol_files:
            proto_module = __import__(p_file.replace("%s\\" % (PROTOCOLS_DIR,), "").replace(".py", ""))
            self._protocols.append(proto_module.Protocol())
        
        self._cal.register_protocols(self._protocols)
        
    def handoff(self):
        '''
        @summary: Calls the handoff function in each one of the protocols.
        '''
        for proto in self._protocols:
            proto.handoff()


if '__main__' == __name__:
    g_pyreshark = PyreShark() #Must be a global so it isn't Auto-Garbage-Collected