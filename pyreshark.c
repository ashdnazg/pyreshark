/* pyreshark.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pyreshark.h"
#include "param_structs.h"




#include <Python.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/filesystem.h>


int g_num_dissectors = 0;
py_dissector_t ** g_dissectors = NULL;


void
init_pyreshark(void)
{
    char * py_init_path;
    char * python_cmd;
    PyObject* py_init_file;
    
    Py_Initialize();
    
    python_cmd = g_strdup_printf("import sys;sys.path.append(\'%s\')", get_datafile_path(PYTHON_DIR));
    PyRun_SimpleString(python_cmd);
    g_free(python_cmd);
    
    py_init_path = get_datafile_path(PYTHON_DIR G_DIR_SEPARATOR_S PYRESHARK_INIT_FILE);
    py_init_file = PyFile_FromString((char *)py_init_path, (char *)"rb");
    

    if (NULL == py_init_file) 
    {
        printf("Can't open Pyreshark init file: %s\n", py_init_path);
        g_free(py_init_path);
        return;
    }
    g_free(py_init_path);

    PyRun_SimpleFileEx(PyFile_AsFile(py_init_file), PYRESHARK_INIT_FILE, TRUE);
    Py_DECREF(py_init_file);
    
}


void
handoff_pyreshark(void)
{
    PyRun_SimpleString("g_pyreshark.handoff()");
}

void 
dissect_pyreshark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i;
    
    for (i=0;i<g_num_dissectors; i++)
    {
        if (strcmp(g_dissectors[i]->name, pinfo->current_proto) == 0)
        {
            dissect_proto(g_dissectors[i], tvb, pinfo, tree);
            return;
        }
    }
    
    if (tree)
    {
        expert_add_info_format(pinfo, NULL, PI_MALFORMED,
                    PI_ERROR, "PyreShark: protocol %s not found",
                    pinfo->current_proto);
    }
}

void 
dissect_proto(py_dissector_t *py_dissector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i;
    int offset = 0;
    tvb_and_tree_t tvb_and_tree = {tvb, tree};;
    
    for (i=0;i<py_dissector->length;i++)
    {
        py_dissector->dissection_chain[i]->func(&tvb_and_tree, pinfo, &offset, py_dissector->dissection_chain[i]->params);
    }
}


void 
register_dissectors_array(int num_dissectors, py_dissector_t ** dissectors_array)
{
    g_num_dissectors = num_dissectors;
    g_dissectors = dissectors_array;
}


void
add_tree_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, add_tree_item_params_t *params)
{
    params->out_item = proto_tree_add_item(tvb_and_tree->tree, *(params->p_hf_index), tvb_and_tree->tvb, *p_offset, params->length, params->encoding);
}

void
add_text_item(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, add_text_item_params_t *params)
{
    params->out_item = proto_tree_add_none_format(tvb_and_tree->tree, *(params->p_hf_index), tvb_and_tree->tvb, *p_offset, params->length, "%s", params->text);
}

void
push_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, push_tree_params_t *params)
{
    if (tvb_and_tree->tree)
    {
        params->out_tree = proto_item_add_subtree(*(params->parent), *(params->p_index));
        tvb_and_tree->tree = params->out_tree;
        *(params->p_start_offset) = *p_offset;
    }
}

void
pop_tree(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_, int *p_offset, pop_tree_params_t *params)
{
    if (tvb_and_tree->tree)
    {
        proto_item_set_len(tvb_and_tree->tree, *p_offset - *(params->p_start_offset));
        tvb_and_tree->tree = tvb_and_tree->tree->parent;
    }
}

void 
advance_offset(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo _U_ , int *p_offset, advance_offset_params_t *params)
{
    if (params->flags == OFFSET_FLAGS_READ_LENGTH || params->flags == OFFSET_FLAGS_READ_LENGTH_INCLUDING) 
    {
        *p_offset += get_uint_value(tvb_and_tree->tvb, *p_offset, params->length, params->encoding);
    }
    if (params->flags == OFFSET_FLAGS_NONE || params->flags == OFFSET_FLAGS_READ_LENGTH) 
    {
        *p_offset += params->length;
    }
}

void
set_column_text(tvb_and_tree_t *tvb_and_tree _U_, packet_info *pinfo, int *p_offset _U_, set_column_text_params_t *params)
{
    if (check_col(pinfo->cinfo, params->col_id))
    {
        col_set_str(pinfo->cinfo, params->col_id, params->text);
    }
}

void call_next_dissector(tvb_and_tree_t *tvb_and_tree, packet_info *pinfo, int *p_offset, call_next_dissector_params_t *params)
{
    char *temp_name = *(params->name);
    gint temp_length = *(params->length);
    *(params->name) = params->default_name;
    *(params->length) = params->default_length;
    call_dissector(find_dissector(temp_name), tvb_new_subset(tvb_and_tree->tvb, *p_offset, temp_length, temp_length), pinfo, tvb_and_tree->tree);
}

guint32
get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding)
{
    switch (length) {
    
    case 1:
        return tvb_get_guint8(tvb, offset);
    case 2:
        return encoding ? tvb_get_letohs(tvb, offset)
                : tvb_get_ntohs(tvb, offset);
    case 3:
        return encoding ? tvb_get_letoh24(tvb, offset)
                : tvb_get_ntoh24(tvb, offset);
    case 4:
        return encoding ? tvb_get_letohl(tvb, offset)
                : tvb_get_ntohl(tvb, offset);
    default:
        return 0;
    }
}
