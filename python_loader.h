/* python_loader.h
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
 
#ifndef __PYTHON_LOADER_H__
#define __PYTHON_LOADER_H__ 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <file.h>

#ifdef _WIN32
    #define PYTHON_27 "python27"
    #define PYTHON_26 "python26"
#else
    #define PYTHON_27 "libpython2.7.so.1.0"
    #define PYTHON_26 "libpython2.6.so.1.0"
#endif


typedef struct python_lib_s {
    void (*Py_Initialize)(void);
    int (*PyRun_SimpleStringFlags)(const char *, void *);
    void * (*PyFile_FromString)(char *, char *);
    FILE * (*PyFile_AsFile)(void *);
    int (*PyRun_SimpleFileExFlags)(FILE *, const char *, int, void *);
    void (*Py_DecRef)(void *);
    void * (*PyImport_ImportModule)(const char *);
} python_lib_t;

typedef enum python_version_e {
    PYTHON_VERSION_27,                       //Don't read the length from the packet
    PYTHON_VERSION_26,                //The value of the length field doesn't include its own bytes.
} python_version_t;


python_lib_t * load_python(python_version_t * version);

#ifdef __cplusplus
}
#endif

#endif
