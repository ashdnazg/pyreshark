'''
@summary: This is a dummy protocol so one can check whether pyreshark initialized succesfully by filtering "pyreshark".
'''
# dummy_protocol.py
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

from cal.cal_types import ProtocolBase

class Protocol(ProtocolBase):
    def __init__(self):
        self._name = "pyreshark"
        self._filter_name = "pyreshark"
        self._short_name = "PYRESHARK"
        self._items = []

