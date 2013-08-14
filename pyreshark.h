/* pyreshark.h
 *
 * Pyreshark Plugin for Wireshark. (http://code.google.com/p/pyreshark)
 *
 * Copyright (c) 2013 by Eshed Shaham
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PYRESHARK_H__
#define __PYRESHARK_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/packet.h>

#include "param_structs.h"

#if VERSION_MINOR > 8
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#else
#define WS_DLL_PUBLIC G_MODULE_EXPORT
#endif

#define PYTHON_DIR "python"
#define PYRESHARK_INIT_FILE "pyreshark.py"



/**
    Used to identify FT_UINT_BYTES and FT_UINT_STRING, or any other future length preceded value.
*/

typedef struct tvb_and_tree_s {
    tvbuff_t *tvb;
    proto_tree *tree;
} tvb_and_tree_t;


/**
    The function type used in the dissection chain
*/
typedef void (*dissect_func_t)(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, void *params);

/**
    A dissection node holdss a function that will be called with the currently dissected packet and the supplied params.
    'params' should fit the function i.e. if the function is 'add_tree_item, params should be of type add_tree_item_params_t.
    See param_structs.h for the declaration of all param's types.
*/
typedef struct dissection_node_s {
    dissect_func_t func;
    void *params;
} dissection_node_t;

typedef struct py_dissector_s {
    dissection_node_t ** dissection_chain; /* A pointer to the array of dissection_node_t's */
    int length; /* The length of the aforementioned array */
    char *name; /* The name of the protocol */
} py_dissector_t;

/** 
    Initializes Python and executes pyreshark.py (which eventually registers all python protocols).
    Called when pyreshark registers protocols
*/
void init_pyreshark(void);

/**
    Registers the python dissectors for later use in 'dissect_pyreshark'.
*/
WS_DLL_PUBLIC void register_dissectors_array(int num_dissectors, py_dissector_t ** dissector_array);

/** 
    Tells the python code to handoff its protocols.
*/
void handoff_pyreshark(void);

/**
    Pyreshark's dissection function shared between all python protocols.
    It determines which protocol should be dissected and calls 'dissect_proto'
*/
WS_DLL_PUBLIC void dissect_pyreshark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/** 
    Goes through the protocol's dissection chain and calls the dissection functions.
*/
void dissect_proto(py_dissector_t * dissector_array, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*****************************************/
/*                                       */
/*          Dissection Functions         */
/*                                       */
/*****************************************/

/**
    Adds an item to the tree.
*/
WS_DLL_PUBLIC void add_tree_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, add_tree_item_params_t *params);

/**
    Adds a line of text to the tree.
*/
WS_DLL_PUBLIC void add_text_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, add_text_item_params_t *params);

/**
    Creates a new subtree.
*/
WS_DLL_PUBLIC void push_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, push_tree_params_t *params);

/**
    Goes up one level in the tree.
*/
WS_DLL_PUBLIC void pop_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, pop_tree_params_t *params);

/**
    Advances the current offset.
*/
WS_DLL_PUBLIC void advance_offset(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, advance_offset_params_t *params);

/**
    Sets the text of a specified column.
*/
WS_DLL_PUBLIC void set_column_text(tvb_and_tree_t *tvb_and_tree _U_, packet_info *pinfo, int *p_offset _U_, set_column_text_params_t *params);

/**
    Calls the next dissector.
*/
WS_DLL_PUBLIC void call_next_dissector(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, call_next_dissector_params_t *params);

/**
    Creates a new data source.
*/
WS_DLL_PUBLIC void push_tvb(tvb_and_tree_t *tvb_and_tree _U_, packet_info *pinfo, int *p_offset _U_, push_tvb_params_t *params);

/**
    Returns to the previous data source.
*/
WS_DLL_PUBLIC void pop_tvb(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, pop_tvb_params_t *params);


/**
    I'd have loved to use the exact same function that exists in proto.c but unfortunately it isn't exported,
    so I had to copy it. :(
*/
guint32 get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding);

#ifdef __cplusplus
}
#endif

#endif
