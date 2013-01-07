'''
@summary: Declares all the ctypes counterparts to Wireshark's Structures
'''

from ctypes import POINTER, Structure, Union, c_int, c_uint, c_uint8, c_ubyte, c_uint16, c_uint32, c_uint64, c_size_t, c_void_p, c_int32, c_char_p, c_double

class WStvb_backing(Structure):
    pass

class WStvb_comp(Structure):
    pass
    
class WUtvbuff_tvbuffs(Union):
    pass
    
class WStvbuff(Structure):
    pass

class WSaddress(Structure):
    pass

class WSpacket_info(Structure):
    pass
    
class WSpacket_info_flags(Structure):
    pass

class WSheader_field_info(Structure):
    pass

class WShf_register_info(Structure):
    pass
    
class WSfield_info(Structure):
    pass
    
class WUfvalue_value(Union):
    pass

class WSfvalue(Structure):
    pass

class WSipv4_addr(Structure):
    pass
    
class WSipv6_addr(Structure):
    pass
    
class WSe_guid(Structure):
    pass
    
class WSns_time(Structure):
    pass
    
class WStree_data(Structure):
    pass
    
class WSproto_node(Structure):
    pass

    
    
WStvb_backing._fields_ = [("tvb", POINTER(WStvbuff)),
                          ("offset", c_int),
                          ("length", c_int)]

WStvb_comp._fields_ = [("tvbs", c_size_t), # GLIB LISTS NOT IMPLEMENTED FOR NOW
                       ("start_offsets", POINTER(c_int)),
                       ("end_offsets", POINTER(c_int))]

WUtvbuff_tvbuffs._fields_ = [("subset", WStvb_backing),
                             ("composite", WStvb_comp)]
                      
                      
WStvbuff._fields_ = [("next", POINTER(WStvbuff)),
                     ("previous", POINTER(WStvbuff)),
                     ("type", c_uint),
                     ("initialized", c_int),
                     ("ds_tvb", POINTER(WStvbuff)),
                     ("tvbuffs", WUtvbuff_tvbuffs),
                     ("real_data", POINTER(c_uint8)),
                     ("length", c_int),
                     ("reported_length", c_int),
                     ("raw_offset", c_int),
                     ("free_cb", c_size_t)]
                     
                     
WSaddress._fields_ = [("type", c_uint),
                      ("len", c_int),
                      ("data", c_void_p)]
                      
WSpacket_info._fields_ = [("current_proto", c_char_p),
                          ("cinfo", c_void_p),   # Column info
                          ("fd", c_void_p), # Frame data
                          ("pseudo_header", c_void_p),
                          ("data_src", c_void_p),
                          ("dl_src", WSaddress),
                          ("dl_dst", WSaddress),
                          ("net_src", WSaddress),
                          ("net_dst", WSaddress),
                          ("src", WSaddress),
                          ("dst", WSaddress),
                          ("ethertype", c_uint32),
                          ("ipproto", c_uint32)]
                          # THE REST IS NOT IMPLEMENTED, don't try to initialize new pinfo's.
                          
WSheader_field_info._fields_ = [("name", c_char_p),
                                ("abbrev", c_char_p),
                                ("type", c_int),
                                ("display", c_int),
                                ("strings", c_void_p),
                                ("bitmask", c_int32),
                                ("blurb", c_char_p), # Brief description of the field
                                # The following parameters should be initialized to 0,0,0,0,None,None
                                # There's a nice const tuple for that named HFILL in ws_consts.py
                                ("id", c_int),
                                ("parent", c_int),
                                ("ref_type", c_int),
                                ("bitshift", c_int),
                                ("same_name_next", POINTER(WSheader_field_info)),
                                ("same_name_prev", POINTER(WSheader_field_info))]
                                
WShf_register_info._fields_ = [("p_id", POINTER(c_int)),
                               ("hfinfo", WSheader_field_info)]
                               
WSe_guid._fields_ = [("data1", c_uint32),
                     ("data2", c_uint16),
                     ("data3", c_uint16),
                     ("data4", 8*c_uint8)]
                     
WSns_time._fields_ = [("secs", c_int), # Should work on most systems
                      ("nsecs", c_int)]
                      
WSipv4_addr._fields_ = [("addr", c_uint32),
                        ("nmask", c_uint32)]
                        
WSipv6_addr._fields_ = [("addr", c_uint32),
                        ("prefix", c_uint32)]
                        
WUfvalue_value._fields_ = [("uinteger", c_uint32),
                           ("sinteger", c_int32),
                           ("integer64", c_uint64),
                           ("floating", c_double),
                           ("string", c_char_p),
                           ("ustring", POINTER(c_ubyte)), # Even though it's actually a string...
                           ("bytes", c_void_p),
                           ("ipv4", WSipv4_addr),
                           ("ipv6", WSipv6_addr),
                           ("guid", WSe_guid),
                           ("time", WSns_time),
                           ("tvb", POINTER(WStvbuff)),
                           ("re", c_void_p)]
                           
WSfvalue._fields_ = [("ftype", c_void_p),
                     ("value", WUfvalue_value),
                     ("fvalue_gboolean1", c_int)] # That's the original name in Wireshark's source. SRSLY WTF?????
                     
WSfield_info._fields_ = [("hfinfo", POINTER(WSheader_field_info)),
                         ("start", c_int),
                         ("length", c_int),
                         ("appendix_start", c_int),
                         ("appendix_length", c_int),
                         ("tree_type", c_int),
                         ("rep", c_void_p), # String for GUI tree
                         ("flags", c_uint32),
                         ("ds_tvb", POINTER(WStvbuff)),
                         ("value", WSfvalue)]
                         
WStree_data._fields_ = [("interesting_hfids", c_void_p),
                        ("visible", c_int),
                        ("fake_protocols", c_int),
                        ("count", c_int)]

WSproto_node._fields_ = [("first_child", POINTER(WSproto_node)),
                         ("last_child", POINTER(WSproto_node)),
                         ("next", POINTER(WSproto_node)),
                         ("parent", POINTER(WSproto_node)),
                         ("finfo", POINTER(WSfield_info)),
                         ("tree_data", POINTER(WStree_data))]
                         
WSproto_tree = WSproto_node
WSproto_item = WSproto_node