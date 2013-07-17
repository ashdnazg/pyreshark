'''
@summary: Here's where most of the logic exists. A bunch of classes providing a simple python interface hiding Wireshark's.
'''
# cal_types.py
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

from ctypes import POINTER, pointer, c_int, c_char, addressof, c_char_p, c_void_p
from struct import unpack, calcsize
from ps_types import PStvbuff_and_tree, PSdissect_func, PS_DISSECT_FUNC_ARGS
from ws_types import WSheader_field_info, WShf_register_info, WSvalue_string, WStrue_false_string, WSrange_string
from param_structs import PSadd_tree_item_params, PSadd_text_item_params, PSpush_tree_params, PSpop_tree_params, PSpush_tvb_params, PSpop_tvb_params, PSadvance_offset_params, PSset_column_text_params, PScall_next_dissector_params
from cal_consts import ENC_READ_LENGTH, TOP_TREE, DEFAULT_TREE, AUTO_TREE, NO_MASK, FIELD_TYPES_DICT, NEW_INDEX, OFFSET_FLAGS_READ_LENGTH, OFFSET_FLAGS_NONE
from ws_consts import HFILL, COL_PROTOCOL, ENC_BIG_ENDIAN, ENC_NA, FT_NONE, DATA, REMAINING_LENGTH, BASE_RANGE_STRING


class ItemBase(object):
    '''
    @summary: The base class for the items in the dissection tree.
    '''
    def __init__(self):
        pass
        
    def register_cal(self, cal):
        '''
        @summary: Registers the cal for later use.
        @param cal: A CAL object.
        '''
        self._cal = cal
        for subitem in getattr(self, "_subitems", []):
            subitem.register_cal(cal)
            
    def register_proto(self, proto):
        '''
        @summary: Registers the item's parent protocol for later use.
        @param proto: A protocol object.
        '''
        self._proto = proto
        for subitem in getattr(self, "_subitems", []):
            subitem.register_proto(proto)
            
    def generate_filter_name(self, prefix):
        '''
        @summary: Generates the item's filter name according to the item's name and the given prefix
        '''
        if hasattr(self, "_name"):
            if prefix != "":
                self._filter_name = ".".join((prefix, self._name))
            else:
                self._filter_name = self._name
                
    def get_node_list(self):
        '''
        @summary: Returns the node list for the dissection of the item.
        @return: A list of tuples of the form (func, params).
        func can be either a C dissect_func_t or a PSdissect_func.
        params can be either the appropriate params' structure for func or None if there isn't one.
        '''
        return []
        
class ProtocolBase(object):
    '''
    @summary: The base class for all the python protocols.
    '''
    def __init__(self):
        '''
        @summary: When you make a Protocol class inheriting ProtocolBase, be sure that the c'tor initializes _name and _items
        '''
        raise Exception("Protocols must have a constructor initializing the members: self._name, self._items")
        
    def register(self, cal):
        '''
        @summary: Registers the protocol and its fields in Wireshark.
        @param cal: A CAL object.
        '''
        if not (hasattr(self, "_name") and hasattr(self, "_items")):
            raise Exception("Protocols must have a constructor initializing the members: self._name, self._items")
        
        if not hasattr(self, "_short_name"):
            self._short_name = self._name.upper().replace(" ","")
        
        if not hasattr(self, "_filter_name"):
            self._filter_name = self._name.lower().replace(" ","")
        
        if not hasattr(self, "_hidden"):
            self._hidden = False
        
        self._cal = cal
        
        self.trees_dict = {TOP_TREE : c_int(NEW_INDEX)}
        
        self.fields_dict = {}
        
        self._proto_index = c_int(cal.wslib.proto_register_protocol(self._name, self._short_name, self._filter_name))
        cal.wslib.register_dissector(self._filter_name, cal.pslib.dissect_pyreshark, self._proto_index)
        
        self._top_tree = Subtree(GeneralItem(pointer(self._proto_index), self._filter_name), self._items, TOP_TREE)
        self._top_tree.generate_filter_name("")
        self._top_tree.register_cal(cal)
        self._top_tree.register_proto(self)
        
        if not hasattr(self, "_next_dissector"):
            self._next_dissector = DissectorItem(DATA, REMAINING_LENGTH)
        
        self._next_dissector.register_cal(cal)
        self._next_dissector.register_proto(self)
        
        trees_array_type = POINTER(c_int) * len(self.trees_dict)
        self._trees_index_array = trees_array_type(*[pointer(tree_index) for tree_index in self.trees_dict.values()])
        cal.wslib.proto_register_subtree_array(self._trees_index_array, len(self._trees_index_array))
        
        hf_array_type = WShf_register_info * len(self.fields_dict)
        self._hf_array = hf_array_type(*self.fields_dict.values())
        cal.wslib.proto_register_field_array(self._proto_index, self._hf_array, len(self._hf_array))
        
    def handoff(self):
        '''
        @summary: Register the protocol in a dissection table according to the member _register_under
        '''
        if hasattr(self, "_register_under"):
            handle = self._cal.wslib.create_dissector_handle(self._cal.pslib.dissect_pyreshark, self._proto_index)
            for table, value in self._register_under.iteritems():
                if type(value) == int:
                    self._cal.wslib.dissector_add_uint(table, value, handle)
                else:
                    self._cal.wslib.dissector_add_string(table, str(value), handle)
    
    def get_node_list(self):
        '''
        @summary: Constructs the node list fro the dissection of this protocol according to its items.
        @return: A list of tuples of the form (func, params).
        func can be either a C dissect_func_t or a PSdissect_func.
        params can be either the appropriate params' structure for func or None if there isn't one.
        '''
        
        if self._hidden:
            temp_nodes_list = []
            for item in self._items:
                temp_nodes_list.extend(item.get_node_list())
        else:
            temp_nodes_list = [(self._cal.pslib.set_column_text, PSset_column_text_params(COL_PROTOCOL, self._short_name))] + \
                                self._top_tree.get_node_list()
            
        self._node_list = temp_nodes_list + self._next_dissector.get_node_list()
        return self._node_list
        
    
    
    def set_next_dissector(self, name, length = REMAINING_LENGTH):
        '''
        @summary: Changes which dissector will be called after the current.
        @param name: A protocol's name
        @param length: The number of bytes to be dissected.
        '''
        if not hasattr(self, "_next_dissector"):
            self._next_dissector = DissectorItem(name, length)
        else:
            self._next_dissector.set(name, length)
                

                
                
class DissectorItem(ItemBase):
    '''
    @summary: An item for calling other dissectors.
    '''
    def __init__(self, name, length = REMAINING_LENGTH):
        '''
        @summary: A constructor.
        @param name: A protocol's name
        @param length: The number of bytes to be dissected.
        '''
        self._dissector_name = c_char_p(name)
        self._length = c_int(length)
        self._params = PScall_next_dissector_params(pointer(self._dissector_name), pointer(self._length), name, length)
    
    def set(self, name, length = REMAINING_LENGTH):
        '''
        @summary: Changes which dissector will be called next time this item is invoked.
        @param name: A protocol's name
        @param length: The number of bytes to be dissected.
        '''
        self._dissector_name.value = name
        self._length.value = length
    
    def get_node_list(self):
        '''
        @summary: See ItemBase
        '''
        return [(self._cal.pslib.call_next_dissector, self._params)]
                
class OffsetItem(ItemBase):
    '''
    @summary: An item for advancing the offset.
    '''
    def __init__(self, length, encoding = ENC_BIG_ENDIAN, flags = OFFSET_FLAGS_NONE):
        '''
        @summary: A constructor.
        @param length: Number of bytes by which to advance the offset.
        @param encoding: one of ENC_ relevant for whether it's big endian or little endian. 
        @param flags: Any of OFFSET_FLAGS_*, Useful for length preceded fields.
        '''
        self._params = PSadvance_offset_params(length, encoding, flags)
        
    def get_node_list(self):
        '''
        @summary: See ItemBase
        '''
        return [(self._cal.pslib.advance_offset, self._params)]

        
class GeneralItem(ItemBase):
    '''
    @summary: An item for an already registered field. Useful for the protocol item.
    '''
    def __init__(self, p_hf_index, name, length=0, encoding = ENC_NA):
        '''
        @summary: A constructor.
        @param p_hf_index: A pointer to the index of a registered field.
        @param name: The name of this item.
        @param length: Length of the field in bytes. Note that the offset is not advanced. (default: 0)
        @param encoding: Encoding for reading the field. (default: ENC_BIG_ENDIAN=ENC_NA=0)
        '''
        self._params = PSadd_tree_item_params(p_hf_index, length, encoding, None)
        self.pointer = self._params.out_item
        self._name = name
        
    def get_node_list(self):
        '''
        @summary: See ItemBase
        '''
        return [(self._cal.pslib.add_tree_item, self._params)]

        
class FieldItem(ItemBase):
    '''
    @summary: An item for any wireshark-dissectable field.
    '''
    def __init__(self, name, field_type, full_name = None, descr = None, encoding = None, mask = NO_MASK, display = None, strings = None, length = None):
        '''
        @summary: A constructor.
        @param name: The name of the field. Used for generating the filter name.
        @param field_type: Any of the FT_* from ws_consts.py (also wireshark's ftypes.h).
        @param full_name: The name that'll be shown in the tree. If it is set to None, full_name=name. (default: None)
        @param descr: A short description of the field. If it is set to None, descr=name. (default: None)
        @param encoding: Encoding for reading the field. See ws_consts.py. If it is set to None, a default encoding is picked from FIELD_TYPES_DICT in cal_consts.py. (default: None)
        @param mask: Bit mask. (default: NO_MASK=0)
        @param display: How the field's value will be displayed in the tree. See ws_consts.py. If it is set to None, a default display is picked from FIELD_TYPES_DICT in cal_consts.py. (default: None)
        @param strings: A dictionary for translating the field's value into text. For boolean fields use True and False as keys, for integers use either the values directly or tuples of (min, max) - not both at the same dictionary! (default: None)
        @param length: Length of the field in bytes. If it is set to None, a default length is picked from FIELD_TYPES_DICT in cal_consts.py. (default: None)
        '''
        
        if full_name is None:
            _full_name = name
        else:
            _full_name = full_name
            
        if descr is None:
            _descr = name
        else:
            _descr = descr
            
        self._name = name
        
        if display is None:
            _display = FIELD_TYPES_DICT[field_type].default_display
        else:
            _display = display
            
        if encoding is None:
            _encoding = FIELD_TYPES_DICT[field_type].default_encoding
        else:
            _encoding = encoding
        
        
        _offset_flags = FIELD_TYPES_DICT[field_type].offset_flags
        
        if length is None:
            _length = FIELD_TYPES_DICT[field_type].default_length
        else:
            _length = length
        
        
        if strings is None:
            _strings = None
        else:
            _strings, str_display = self._generate_strings_struct(strings)
            _display |= str_display
        
        self._field = WSheader_field_info(_full_name, None, field_type, _display, _strings, mask, _descr, *HFILL)
        self._index = c_int(NEW_INDEX)
        self._params = PSadd_tree_item_params(pointer(self._index), _length, _encoding, None)
        
        self.pointer = self._params.out_item
        self._offset_params = PSadvance_offset_params(_length, _encoding, _offset_flags)
        
    def generate_filter_name(self, prefix):
        '''
        @summary: See ItemBase.
        '''
        super(FieldItem, self).generate_filter_name(prefix)
        self._field.abbrev = self._filter_name
        
    def register_proto(self, proto):
        '''
        @summary: See ItemBase.
        '''
        super(FieldItem, self).register_proto(proto)
        if self._filter_name not in proto.fields_dict.keys():
            proto.fields_dict[self._filter_name] = WShf_register_info(pointer(self._index), self._field)
        
    def get_node_list(self):
        '''
        @summary: See ItemBase.
        '''
        return [(self._cal.pslib.add_tree_item, self._params),
                (self._cal.pslib.advance_offset, self._offset_params)]

    def _generate_strings_struct(self, strings_dict):
        '''
        @summary: Generates the strings structure in the header_field_info.
        @strings_dict: The dictionary for translating the field's value into text.
        @return: A tuple of the form: (The new structure's address or 'None', the appropriate display flag). 
        '''
        keys_type = None
        str_display = 0
        for key in strings_dict.iterkeys():
            if keys_type is None:
                keys_type = type(key)
            elif keys_type != type(key):
                return (None, 0)
        if keys_type == int:
            vals_array_type = WSvalue_string * (len(strings_dict) + 1)
            self._strings = vals_array_type(*([WSvalue_string(value, s) for value, s in strings_dict.iteritems()] + [WSvalue_string(0,None)]))
        elif keys_type == bool:
            self._strings = WStrue_false_string(strings_dict[True], strings_dict[False])
        elif keys_type == tuple:
            rvals_array_type = WSrange_string * (len(strings_dict) + 1)
            self._strings = rvals_array_type(*([WSrange_string(min, max, s) for (min, max), s in strings_dict.iteritems()] + [WSrange_string(0,0, None)]))
            str_display = BASE_RANGE_STRING
        
        return (addressof(self._strings), str_display)

            
class TextItem(FieldItem):
    def __init__(self, name, text, length = 0):
        '''
        @summary: A constructor.
        @param name: The name of the field. Used for generating the filter name.
        @param text: The text that will be added to the tree.
        @param length: Length of the field in bytes. Note that the offset is not advanced. (default: 0)
        '''
        super(TextItem, self).__init__(name, FT_NONE, length=length)
        self._params = PSadd_text_item_params(pointer(self._index), length, text, None)
        self.pointer = self._params.out_item
        
    def get_node_list(self):
        '''
        @summary: See ItemBase.
        '''
        return [(self._cal.pslib.add_text_item, self._params)]
        
        
class Subtree(ItemBase):
    '''
    @summary: A class for creating subtrees in the dissection tree.
    '''
    def __init__(self, parent_item, item_list, tree_name = AUTO_TREE):
        '''
        @summary: A constructor.
        @param parent_item: The subtree's parent item.
        @param item_list: The subtree's children - A list of items.
        @param tree_name: Used by Wireshark for remembering which trees are expanded. Put AUTO_TREE for the name of parent_item. (default: AUTO_TREE)
        '''
        self.start_offset = c_int(0)
        self._params = PSpush_tree_params(pointer(parent_item.pointer), None, pointer(self.start_offset), None)
        self._pop_params = PSpop_tree_params(pointer(self.start_offset))
        self._subitems = [parent_item] + item_list
        self._tree_name = tree_name
        
    def register_proto(self, proto):
        '''
        @summary: See ItemBase.
        '''
        super(Subtree, self).register_proto(proto)
        if self._tree_name == AUTO_TREE:
            self._tree_name = self.get_parent_item()._filter_name
        if self._tree_name not in proto.trees_dict.keys():
            proto.trees_dict[self._tree_name] = c_int(NEW_INDEX)
        self._params.p_index = pointer(proto.trees_dict[self._tree_name])
        
    def generate_filter_name(self, prefix):
        '''
        @summary: See ItemBase.
        '''
        self.get_parent_item().generate_filter_name(prefix)
        new_prefix = self.get_parent_item()._filter_name
        for item in self.get_child_items():
            item.generate_filter_name(new_prefix)
            
    def get_node_list(self):
        '''
        @summary: See ItemBase.
        '''
        node_list = self.get_parent_item().get_node_list() + [(self._cal.pslib.push_tree, self._params)]
        for item in self.get_child_items():
            node_list.extend(item.get_node_list())
        node_list.extend([(self._cal.pslib.pop_tree, self._pop_params)])
        return node_list
        
    def get_parent_item(self):
        return self._subitems[0]
        
    def get_child_items(self):
        return self._subitems[1:]

class ColumnItem(ItemBase):
    '''
    @summary: Changes the text of a column
    '''
    def __init__(self, col_id, text):
        '''
        @summary: A constructor.
        @param col_id: The column's id (any COL_* from ws_consts.py).
        @param text: The new text of the column.
        '''
        self._params = PSset_column_text_params(col_id, text)
    
    def get_node_list(self):   
        '''
        @summary: See ItemBase.
        '''
        return [(self._cal.pslib.set_column_text, self._params)]
        

class PyFunctionItem(ItemBase):
    '''
    @summary: Adds a python function to the dissection.
    '''
    def __init__(self, dissection_func, items_dict = {}):
        '''
        @summary: A constructor.
        @param dissection_func: A python function. It'll be called with a single parameter: a Packet instance.
        @param items_dict: A dictionary of all the items the function might read. The keys can be anything and will be used when the function calls packet.read_item(key).
        '''
        self._dissection_func = dissection_func
        self._c_callback = PSdissect_func(self._callback)
        self._subitems = items_dict.values()
        self._items_dict = items_dict
        
    def generate_filter_name(self, prefix):
        '''
        @summary: See ItemBase.
        '''
        for subitem in getattr(self, "_subitems", []):
            subitem.generate_filter_name(prefix)
    
    def get_node_list(self):
        '''
        @summary: See ItemBase.
        '''
        return [(self._c_callback, None)]
        
    def _callback(self, p_tvb_and_tree, p_pinfo, p_offset, params):
        '''
        @summary: The callback that will be called from the C code. Don't call this directly.
        '''
        p = Packet(p_tvb_and_tree.contents.tvb, p_tvb_and_tree.contents.tree, p_pinfo, p_offset, self._cal, self._items_dict)
        self._dissection_func(p)
        p_tvb_and_tree.contents.tvb = p.p_new_tvb
        p_tvb_and_tree.contents.tree = p.p_new_tree
        p_offset.contents.value = p.offset
        

class SubSource(ItemBase):
    '''
    @summary: Adds a new data source from which the sub-fields will be read
    '''
    def __init__(self, source_name, create_data_func, items_list):
        '''
        @summary: A constructor.
        @param create_data_func: The python function that returns the new source's bytes as a string. It'll be called with a single parameter: a Packet instance.
        @param items_list: A list of the items that will be read from the new source.
        '''
        self._create_data_func = create_data_func
        self._c_callback = PSdissect_func(self._callback)
        self._subitems = items_list
        
        self.old_offset = c_int(0)
        self.old_tvb = c_void_p(0)
        self._push_params = PSpush_tvb_params(source_name, None, 0, pointer(self.old_offset), pointer(self.old_tvb))
        self._pop_params = PSpop_tvb_params(pointer(self.old_offset), pointer(self.old_tvb))
        
    def generate_filter_name(self, prefix):
        '''
        @summary: See ItemBase.
        '''
        for subitem in getattr(self, "_subitems", []):
            subitem.generate_filter_name(prefix)
    
    def get_node_list(self):
        '''
        @summary: See ItemBase.
        '''
        node_list = [(self._c_callback, None), (self._cal.pslib.push_tvb, self._push_params)]
        for item in self._subitems:
            node_list.extend(item.get_node_list())
        node_list.extend([(self._cal.pslib.pop_tvb, self._pop_params)])
        return node_list
        
    def _callback(self, p_tvb_and_tree, p_pinfo, p_offset, params):
        '''
        @summary: The callback that will be called from the C code. Don't call this directly.
        '''
        p = Packet(p_tvb_and_tree.contents.tvb, p_tvb_and_tree.contents.tree, p_pinfo, p_offset, self._cal, None)
        self._data = self._create_data_func(p)
        self._push_params.data = self._data
        self._push_params.length = len(self._data)
        p_offset.contents.value = p.offset

        
class Packet(object):
    '''
    @summary: This class provides a comfortable interface for the python dissection functions.
    '''
    def __init__(self, p_tvb, p_tree, p_pinfo, p_offset, cal, items_dict):
        '''
        @summary: A constructor.
        @param p_tvb: A pointer to the tvbuff.
        @param p_tree: A pointer to the tree.
        @param p_pinfo: A pointer to the packet_info.
        @param p_offset: A pointer to the current offset.
        @param cal: A CAL object.
        @param items_dict: A dictionary of all items that might be read in this packet
        '''
        self._cal = cal
        self._p_tvb = p_tvb
        self._p_tree = p_tree
        self._p_pinfo = p_pinfo
        self.offset  = p_offset.contents.value
        self.p_new_tvb = p_tvb
        self.p_new_tree = p_tree
        self.buffer = self._init_buffer(p_tvb)
        self._items_dict = items_dict
        
        self.id = self._p_pinfo.contents.fd.contents.num
        self.visited = self._p_pinfo.contents.fd.contents.flags.visited
        
    def _init_buffer(self, p_tvb):
        '''
        @summary: Adds a new text item to the tree.
        @param p_tvb: A pointer to the tvbuff.
        @return: The tvb's bytes as a string.
        '''
        length = p_tvb.contents.length
        byte_array = (c_char * length).from_address(addressof(p_tvb.contents.real_data.contents))
        return byte_array.raw
        
    def add_text(self, text, length = 0, offset = None):
        '''
        @summary: Adds a new text item to the tree.
        @param text: The text to be added.
        @param length: The number of bytes that'll be marked when selecting the item. The packet's offset is not advanced. (default: 0)
        @param offset: The beginning offset for the marked bytes. If set to None, offset=self.offset. (default: None)
        '''
        if offset is None:
            _offset = self.offset
        else:
            _offset = offset
        self._cal.wslib.proto_tree_add_text(self.p_new_tree, self.p_new_tvb, _offset, length, text)
    
    def set_column_text(self, col_id, text):
        '''
        @summary: Sets a column's text.
        @param col_id: The column's id (any COL_* from ws_consts.py).
        @param text: The new text of the column.
        '''
        
        #offset and tvb_and_tree passed as zero and None respectively, since it doesn't really matter
        self._cal.pslib.set_column_text(None, self._p_pinfo, 0, pointer(PSset_column_text_params(col_id, text)))
    
    def read_item(self, item_key):
        '''
        @summary: Reads an item from the items dictionary passed to PyFunctionItem, adds it to the tree and advances the offset.
        @param item_key: The key of the item in the items_dict
        '''
        node_list = self._items_dict[item_key].get_node_list()
        temp_offset = pointer(c_int(self.offset))
        tvb_and_tree = pointer(PStvbuff_and_tree(self.p_new_tvb, self.p_new_tree))
        for func, params in node_list:
            if params is None:
                p_params = None
            else:
                p_params = addressof(params)
            func.argtypes = PS_DISSECT_FUNC_ARGS
            func(tvb_and_tree, self._p_pinfo, temp_offset, p_params)
        
        self.offset = temp_offset.contents.value
    
    def unpack(self, format, offset = None):
        '''
        @summary: Unpacks values from the packet's buffer, using struct.unpack
        @param format: A format string. (see Python's documentation for the module struct)
        @param offset: The offset from which the values will be read. None will set it to the current offset. (default: None)
        '''
        if offset is None:
            _offset = self.offset
        else:
            _offset = offset
            
        return unpack(format, self.buffer[_offset:_offset+calcsize(format)])
