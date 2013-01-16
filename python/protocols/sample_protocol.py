'''
@summary: A sample protocol, it's a very thinned down version of ARP.
'''
# sample_protocol.py
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

from cal.cal_types import ProtocolBase, FieldItem, PyFunctionItem, Subtree, TextItem
from cal.ws_consts import FT_UINT16, BASE_HEX, FT_UINT8, FT_ETHER, FT_IPv4

ETHERNET = 1
IP = 0x0800

class Protocol(ProtocolBase):
    def __init__(self):
        self._name = "Pyreshark Sample Protocol (ARP)"
        self._filter_name = "pysample"
        self._short_name = "PYSAMPLE"
        self._items = [FieldItem("hw.type", FT_UINT16, "Hardware Type"),
                       FieldItem("proto.type", FT_UINT16, "Protocol Type", display = BASE_HEX),
                       FieldItem("hw.size", FT_UINT8, "Hardware Size"),
                       FieldItem("proto.size", FT_UINT8, "Protocol Size"),
                       FieldItem("opcode", FT_UINT16, "Opcode"),
                       Subtree(TextItem("src", "Sender"), [PyFunctionItem(self.add_addresses, { "mac" : FieldItem("hw_mac", FT_ETHER, "Sender MAC Address"),
                                                                                                "ip" : FieldItem("proto_ipv4", FT_IPv4, "Sender IP Address"),})]),
                       Subtree(TextItem("dst", "Target"), [PyFunctionItem(self.add_addresses, { "mac" : FieldItem("hw_mac", FT_ETHER, "Target MAC Address"),
                                                                                                "ip" : FieldItem("proto_ipv4", FT_IPv4, "Target IP Address"),})]),
                       ]
        #self._register_under = { "ethertype": 0x0806} # UNCOMMENT THIS TO TEST THE PROTOCOL

    def add_addresses(self, packet):
        (hw_type, proto_type, hw_size, proto_size) = packet.unpack(">HHBB", 0)
        if hw_type == ETHERNET:
            packet.read_item("mac")
        else:
            packet.add_text("Unimplemented hardware type")
            packet.offset += hw_size
        
        if proto_type == IP:
            packet.read_item("ip")
        else:
            packet.add_text("Unimplemented protocol type")
            packet.offset += proto_size