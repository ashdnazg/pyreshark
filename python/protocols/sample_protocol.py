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
                       PyFunctionItem(self.add_addresses, { "sender_mac" : FieldItem("src.hw_mac", FT_ETHER, "Sender MAC Address"),
                                                            "target_mac" : FieldItem("dst.hw_mac", FT_ETHER, "Target MAC Address"),
                                                            "sender_ip" : FieldItem("src.proto_ipv4", FT_IPv4, "Sender IP Address"),
                                                            "target_ip" : FieldItem("dst.proto_ipv4", FT_IPv4, "Target IP Address"),
                                                          })
                       ]
        self._register_under = { "ethertype": 0x0806}

    def add_addresses(self, packet):
        (hw_type, proto_type, hw_size, proto_size) = packet.unpack(">HHBB", 0)
        if hw_type == ETHERNET:
            packet.read_item("sender_mac")
        else:
            packet.add_text("Unimplemented hardware type")
            packet.offset += hw_size
        
        if proto_type == IP:
            packet.read_item("sender_ip")
        else:
            packet.add_text("Unimplemented protocol type")
            packet.offset += proto_size
        
        if hw_type == ETHERNET:
            packet.read_item("target_mac")
        else:
            packet.offset += hw_size
        
        if proto_type == IP:
            packet.read_item("target_ip")
        else:
            packet.offset += proto_size