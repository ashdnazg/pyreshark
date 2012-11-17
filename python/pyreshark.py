sys.stdout = open("%s\\..\\out.log" % sys.path[-1],"wb")
sys.stderr = open("%s\\..\\err.log" % sys.path[-1],"wb")

import cal

class PyreShark(object):
    
    def __init__(self):
        self._cal = cal.CAL()


        
def main():
    pass

if '__main__' == __name__:
    g_pyreshark = PyreShark()
    main()