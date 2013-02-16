/* param_structs.c
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
 
#ifndef __PARAM_STRUCTS_H__
#define __PARAM_STRUCTS_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <epan/packet.h>
#include <epan/proto.h>

#include "pyreshark.h"

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


typedef enum offset_flags_e {
    OFFSET_FLAGS_NONE,                       //Don't read the length from the packet
    OFFSET_FLAGS_READ_LENGTH,                //The value of the length field doesn't include its own bytes.
    OFFSET_FLAGS_READ_LENGTH_INCLUDING,      //The value of the length field includes both its own bytes and the data bytes.
} offset_flags_t;

typedef struct advance_offset_params_s {
    int length;
    guint encoding;
    offset_flags_t flags;
} advance_offset_params_t;



typedef struct set_column_text_params_s {
    int col_id;
    char *text;
} set_column_text_params_t;

typedef struct call_next_dissector_params_s {
    char **name;
    gint *length;
    char *default_name;
    gint default_length;
} call_next_dissector_params_t;


#ifdef __cplusplus
}
#endif

#endif 