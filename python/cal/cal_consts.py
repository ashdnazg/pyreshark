'''
@summary: Holds all the constants of the CAL
'''
# cal_consts.py
#
# Pyreshark Plugin for Wireshark. (https://github.com/pyreshark/PyreShark)
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

from ws_consts import *

ENC_READ_LENGTH = 0x00010000
TOP_TREE = "_top"
DEFAULT_TREE = "_default"
AUTO_TREE = "_auto"
NO_MASK = 0
NEW_INDEX = -1

class FieldType(object):
    def __init__(self, default_length, default_display, default_encoding):
        self.default_length = default_length
        self.default_display = default_display
        self.default_encoding = default_encoding
        
        
FIELD_TYPES_DICT = {FT_NONE: FieldType(0, BASE_NONE, ENC_NA),
                    FT_BOOLEAN: FieldType(1, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_UINT8: FieldType(1, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_UINT16: FieldType(2, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_UINT24: FieldType(3, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_UINT32: FieldType(4, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_UINT64: FieldType(8, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_INT8: FieldType(1, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_INT16: FieldType(2, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_INT24: FieldType(3, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_INT32: FieldType(4, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_INT64: FieldType(8, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_FLOAT: FieldType(4, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_DOUBLE: FieldType(8, BASE_DEC, ENC_BIG_ENDIAN),
                    FT_ABSOLUTE_TIME: FieldType(4, ABSOLUTE_TIME_LOCAL, ENC_TIME_TIMESPEC),
                    FT_RELATIVE_TIME: FieldType(4, ABSOLUTE_TIME_LOCAL, ENC_TIME_TIMESPEC),
                    FT_STRING: FieldType(1, BASE_NONE, ENC_ASCII),
                    FT_STRINGZ: FieldType(-1, BASE_NONE, ENC_ASCII),
                    FT_UINT_STRING: FieldType(1, BASE_NONE, ENC_READ_LENGTH | ENC_ASCII | ENC_BIG_ENDIAN),
                    FT_BYTES: FieldType(1, BASE_NONE, ENC_NA),
                    FT_UINT_BYTES: FieldType(1, BASE_NONE, ENC_READ_LENGTH | ENC_NA | ENC_BIG_ENDIAN),
                    FT_IPv4: FieldType(4, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_IPv6: FieldType(16, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_ETHER: FieldType(6, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_IPXNET: FieldType(4, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_EUI64: FieldType(8, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_GUID: FieldType(16, BASE_NONE, ENC_BIG_ENDIAN),
                    FT_OID: FieldType(1, BASE_NONE, ENC_BIG_ENDIAN),
                    }