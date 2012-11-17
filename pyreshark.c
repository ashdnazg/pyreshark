#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pyreshark.h"

#include <Python.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/filesystem.h>


int g_num_dissectors = 0;
py_dissector_t ** g_dissectors = NULL;

static gint proto_dummy_pyreshark = -1; 


void
init_pyreshark()
{
    char * py_init_path;
    char * python_cmd;
    PyObject* py_init_file;
    //FILE * py_init_file;
    
    Py_Initialize();
    
    python_cmd = g_strdup_printf("import sys;sys.path.append(\'%s\')", get_datafile_path(PYTHON_DIR));
    PyRun_SimpleString(python_cmd);
    g_free(python_cmd);
    
    py_init_path = get_datafile_path(PYTHON_DIR G_DIR_SEPARATOR_S PYRESHARK_INIT_FILE);
    py_init_file = PyFile_FromString(py_init_path, "rb");
    //py_init_file = fopen(py_init_path, "rb");
    

    if (NULL == py_init_file) 
    {
        printf("Can't open Pyreshark init file: %s\n", py_init_path);
        g_free(py_init_path);
        return;
    }
    g_free(py_init_path);

    PyRun_SimpleFileEx(PyFile_AsFile(py_init_file), PYRESHARK_INIT_FILE, TRUE);
    Py_DECREF(py_init_file);

    
    
    //PyRun_SimpleFileEx(py_init_file, PYRESHARK_INIT_FILE, TRUE);
    
    //fclose(py_init_file);
    
}


void
handoff_pyreshark()
    
{
    dissector_handle_t pyreshark_handle;
    proto_dummy_pyreshark = proto_register_protocol("Pyreshark", "PYRESHARK", "pyreshark"); 
    register_dissector ("pyreshark", dissect_pyreshark, proto_dummy_pyreshark);
    pyreshark_handle = create_dissector_handle(dissect_pyreshark, proto_dummy_pyreshark); 
    dissector_add_uint("wtap_encap", 1, pyreshark_handle);
}

void 
dissect_pyreshark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i;
    
    for (i=0;i<g_num_dissectors; i++)
    {
        if (strcmp(g_dissectors[i]->name, pinfo->current_proto))
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
dissect_proto(py_dissector_t * py_dissector, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i;
    int offset = 0;
    tvbuff_t *new_tvb = tvb;
    
    for (i=0;i<py_dissector->length;i++)
    {
        new_tvb = py_dissector->dissection_chain[i]->func(new_tvb, pinfo, tree, &offset, py_dissector->dissection_chain[i]->params);
    }
}


void 
register_dissectors_array(int num_dissectors, py_dissector_t ** dissectors_array)
{
    g_num_dissectors = num_dissectors;
    g_dissectors = dissectors_array;
}