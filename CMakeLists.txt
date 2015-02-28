# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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
#

set(DISSECTOR_SRC
    pyreshark.c
    python_loader.c
)

set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
)

set(CLEAN_FILES
    ${PLUGIN_FILES}
)

if (WERROR)
    set_source_files_properties(
        ${CLEAN_FILES}
        PROPERTIES
        COMPILE_FLAGS -Werror
    )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# register_dissector_files(plugin.c
    # plugin
    # ${DISSECTOR_SRC}
# )

ADD_CUSTOM_COMMAND(
    OUTPUT python/cal/ws_consts.py
    COMMAND ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/generate_ws_consts.py 
      python/cal/ws_consts.py
    DEPENDS
      ${CMAKE_CURRENT_SOURCE_DIR}/generate_ws_consts.py
)

ADD_CUSTOM_COMMAND(
    OUTPUT python/cal/ws_types.py
    COMMAND ${CMAKE_COMMAND} -E copy
     ${CMAKE_CURRENT_SOURCE_DIR}/templates/ws_types.py.${CPACK_PACKAGE_VERSION_MAJOR}_${CPACK_PACKAGE_VERSION_MINOR}
     python/cal/ws_types.py
)

add_library(pyreshark ${LINK_MODE_MODULE}
    ${PLUGIN_FILES}
)

set_target_properties(pyreshark PROPERTIES PREFIX "")
set_target_properties(pyreshark PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(pyreshark epan)

add_custom_target(
    pyresharkpython ALL
    DEPENDS
	  python/cal/ws_types.py
      python/cal/ws_consts.py
)

install(TARGETS pyreshark
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

install(DIRECTORY
      python
      ${CMAKE_CURRENT_BINARY_DIR}/python
    DESTINATION
      ${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
)
