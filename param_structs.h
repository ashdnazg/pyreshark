#ifndef __PARAM_STRUCTS_H__
#define __PARAM_STRUCTS_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>

typedef struct add_tree_item_params_s {
    int *p_hf_index;
    gint length;
    guint encoding;
    proto_item *out_item;
} add_tree_item_params_t;

typedef struct add_text_item_params_s {
    int *p_hf_index;
    gint length;
    char *text;
    proto_item *out_item;
} add_text_item_params_t;

typedef struct push_tree_params_s {
    proto_item **parent;
    gint *p_index;
    int *p_start_offset;
    proto_tree *out_tree;
} push_tree_params_t;

typedef struct pop_tree_params_s {
    int *p_start_offset;
} pop_tree_params_t;

typedef struct advance_offset_params_s {
    int length;
    int encoding;
} advance_offset_params_t;

typedef struct set_column_text_params_s {
    int col_id;
    char *text;
} set_column_text_params_t;

typedef struct call_next_dissector_params_s {
    char **name;
    char *default_name;
} call_next_dissector_params_t;


#ifdef __cplusplus
}
#endif

#endif 