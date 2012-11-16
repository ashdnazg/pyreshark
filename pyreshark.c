#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <Python.h>

void
init_pyreshark()
{
    Py_Initialize();
}
