/* python_loader.c
 *
 * Pyreshark Plugin for Wireshark. (https://github.com/ashdnazg/pyreshark)
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

#include "config.h"

#include "python_loader.h"

#include <glib.h>
#include <gmodule.h>

gboolean load_symbol(GModule *handle, const char *function_name, void ** dest)
{
    gpointer gp;
    if (g_module_symbol(handle, function_name, &gp))
    {
        *dest = gp;
        return TRUE;
    } else {
        return FALSE;
    }
}

python_lib_t * load_python_lib(const char * python_lib_name)
{
    GModule *handle = NULL;
    int * _Py_NoSiteFlag = NULL;
    python_lib_t *python_lib = NULL;
    void *site_module;
    
    if ((handle = g_module_open(python_lib_name, (GModuleFlags)0)) == NULL)
    {
        return NULL;
    }
    python_lib = (python_lib_t *) g_malloc(sizeof(python_lib_t));
    if (!load_symbol(handle, "Py_Initialize", (void **) &(python_lib->Py_Initialize)) ||
        !load_symbol(handle, "PyRun_SimpleStringFlags", (void **) &(python_lib->PyRun_SimpleStringFlags)) ||
        !load_symbol(handle, "PyFile_FromString", (void **) &(python_lib->PyFile_FromString)) ||
        !load_symbol(handle, "PyFile_AsFile", (void **) &(python_lib->PyFile_AsFile)) ||
        !load_symbol(handle, "PyRun_SimpleFileExFlags", (void **) &(python_lib->PyRun_SimpleFileExFlags)) ||
        !load_symbol(handle, "Py_DecRef", (void **) &(python_lib->Py_DecRef)) ||
        !load_symbol(handle, "PyImport_ImportModule", (void **) &(python_lib->PyImport_ImportModule)))
    {
        g_free(python_lib);
        g_module_close(handle);
        return NULL;
    }
    
    load_symbol(handle, "Py_NoSiteFlag", (void **) &(_Py_NoSiteFlag));
    ++(*_Py_NoSiteFlag);
    
    python_lib->Py_Initialize();
    site_module = python_lib->PyImport_ImportModule("site");
    
    if (site_module == NULL)
    {
        g_free(python_lib);
        g_module_close(handle);
        return NULL;
    }
    
    python_lib->Py_DecRef(site_module);
    
    return python_lib;
}

python_lib_t * load_python(python_version_t *out_version)
{
    python_lib_t *python_lib = NULL;
    python_lib = load_python_lib(PYTHON_27);
    if (python_lib != NULL)
    {
        *out_version = PYTHON_VERSION_27;
        return python_lib;
    }
    python_lib = load_python_lib(PYTHON_26);
    if (python_lib != NULL)
    {
        *out_version = PYTHON_VERSION_26;
        return python_lib;
    }
    return NULL;
}
