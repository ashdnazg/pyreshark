'''
@summary: A sample protocol, it's a very thinned down version of ARP.
'''
# sample_protocol.py
#
# Pyreshark Plugin for Wireshark. (https://github.com/ashdnazg/pyreshark)
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

from cal.cal_types import ProtocolBase, FieldItem, PyFunctionItem, Subtree, TextItem
from cal.ws_consts import FT_UINT16, BASE_HEX, FT_UINT8, FT_ETHER, FT_IPv4, COL_INFO
from functools import partial

ETHERNET = 1
IP = 0x0800

ARPOP_REQUEST = 1
ARPOP_REPLY = 2

HW_TYPE_STRINGS = {ETHERNET : "Ethernet"}
PROTO_TYPE_STRINGS = {IP : "IP"}
OPCODE_STRINGS =   {ARPOP_REQUEST:  "request",
                    ARPOP_REPLY:    "reply"}

INFO_STRINGS = {ARPOP_REQUEST: "Who has %s? Tell %s",
                ARPOP_REPLY: "%s is at %s"}
                    
class Protocol(ProtocolBase):
    def __init__(self):
        self._name = "Pyreshark Sample Protocol (ARP)"
        self._filter_name = "pysample"
        self._short_name = "PYSAMPLE"
        self._items = [FieldItem("hw.type", FT_UINT16, "Hardware Type", strings = HW_TYPE_STRINGS),
                       FieldItem("proto.type", FT_UINT16, "Protocol Type", display = BASE_HEX, strings = PROTO_TYPE_STRINGS),
                       FieldItem("hw.size", FT_UINT8, "Hardware Size"),
                       FieldItem("proto.size", FT_UINT8, "Protocol Size"),
                       FieldItem("opcode", FT_UINT16, "Opcode", strings = OPCODE_STRINGS),
                       Subtree(TextItem("src", "Sender"), [PyFunctionItem(partial(self.add_addresses, "src"),
                                                                          { "mac" : FieldItem("hw_mac", FT_ETHER, "Sender MAC Address"),
                                                                            "ip" : FieldItem("proto_ipv4", FT_IPv4, "Sender IP Address"),})]),
                       Subtree(TextItem("dst", "Target"), [PyFunctionItem(partial(self.add_addresses, "dst"), 
                                                                          { "mac" : FieldItem("hw_mac", FT_ETHER, "Target MAC Address"),
                                                                            "ip" : FieldItem("proto_ipv4", FT_IPv4, "Target IP Address"),})]),
                       PyFunctionItem(self.append_opcode, {}),
                       ]
        #self._register_under = { "ethertype": 0x0806} # UNCOMMENT THIS TO TEST THE PROTOCOL

    def append_opcode(self, packet):
        (opcode,) = packet.unpack(">H", 6)
        self.append_text(" (%s)" % OPCODE_STRINGS[opcode])
        if opcode == ARPOP_REQUEST:
            packet.set_column_text(COL_INFO, "Who has %s? Tell %s" % (self._target_proto, self._sender_proto))
        elif opcode == ARPOP_REPLY:
            packet.set_column_text(COL_INFO, "%s is at %s" % (self._sender_proto, self._sender_hw))
    
    def add_addresses(self, parent, packet):
        (hw_type, proto_type, hw_size, proto_size) = packet.unpack(">HHBB", 0)
        if hw_type == ETHERNET:
            hw_address = ":".join("%02x" % ord(b) for b in packet.buffer[packet.offset:packet.offset + 6])
            packet.read_item("mac")
        else:
            hw_address = "???"
            packet.add_text("Unimplemented hardware type")
            packet.offset += hw_size
        
        if proto_type == IP:
            proto_address = ".".join("%d" % ord(b) for b in packet.buffer[packet.offset:packet.offset + 4])
            packet.read_item("ip")
        else:
            proto_address = "???"
            packet.add_text("Unimplemented protocol type")
            packet.offset += proto_size
            
        self.append_text(" (%s, %s)" % (hw_address, proto_address), parent)
        
        if parent == "src":
            self._sender_hw = hw_address
            self._sender_proto = proto_address
        elif parent == "dst":
            self._target_hw = hw_address
            self._target_proto = proto_address
