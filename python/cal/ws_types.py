from ctypes import *

class WStvb_backing(Structure):
    pass

class WStvb_comp(Structure):
    pass
    
class WUtvbuffs(Union):
    pass
    
class WStvbuff(Structure):
    pass

    
WStvb_backing._fields_ = [("tvb", POINTER(WStvbuff)),
                          ("offset", c_int),
                          ("length", c_int)]

WStvb_comp._fields_ = [("tvbs", c_size_t), #GLIB LISTS NOT IMPLEMENTED FOR NOW
                       ("start_offsets", POINTER(c_int)),
                       ("end_offsets", POINTER(c_int))]

WUtvbuffs._fields_ = [("subset", WStvb_backing),
                      ("composite", WStvb_comp)]
                      
                      
WStvbuff._fields_ = [("next", POINTER(WStvbuff)),
                     ("previous", POINTER(WStvbuff)),
                     ("type", c_uint),
                     ("initialized", c_int),
                     ("ds_tvb", POINTER(WStvbuff)),
                     ("tvbuffs", WUtvbuffs),
                     ("real_data", POINTER(c_uint8)),
                     ("length", c_int),
                     ("reported_length", c_int),
                     ("raw_offset", c_int),
                     ("free_cb", c_size_t)]