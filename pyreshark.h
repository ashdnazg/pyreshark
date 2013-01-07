#ifndef __PYRESHARK_H__
#define __PYRESHARK_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/packet.h>

#include "param_structs.h"

#define PYTHON_DIR "python"
#define PYRESHARK_INIT_FILE "pyreshark.py"

/**
    Used to identify FT_UINT_BYTES and FT_UINT_STRING, or any other future length preceded value.
*/
#define ENC_READ_LENGTH 0x00010000

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
void init_pyreshark();

/**
    Registers the python dissectors for later use in 'dissect_pyreshark'.
*/
void register_dissectors_array(int num_dissectors, py_dissector_t ** dissector_array);

/** 
    Tells the python code to handoff its protocols.
*/
void handoff_pyreshark();

/**
    Pyreshark's dissection function shared between all python protocols.
    It determines which protocol should be dissected and calls 'dissect_proto'
*/
void dissect_pyreshark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

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
void add_tree_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, add_tree_item_params_t *params);

/**
    Adds a line of text to the tree.
*/
void add_text_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, add_text_item_params_t *params);

/**
    Creates a new subtree.
*/
void push_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, push_tree_params_t *params);

/**
    Goes up one level in the tree.
*/
void pop_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, pop_tree_params_t *params);

/**
    Advances the current offset.
*/
void advance_offset(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, advance_offset_params_t *params);

/**
    Sets the text of a specified column.
*/
void set_column_text(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, set_column_text_params_t *params);

/**
    Calls the next dissector.
*/
void call_next_dissector(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, call_next_dissector_params_t *params);


/**
    I'd have loved to use the exact same function that exists in proto.c but unfortunately it isn't exported,
    so I had to copy it. :(
*/
guint32 get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding);

/**
    A daft hack so python can treat C and Python callabacks to dissection functions the same.
    The function just returns the value it recieves.
*/
void * get_pointer(void *callback);

#ifdef __cplusplus
}
#endif

#endif 