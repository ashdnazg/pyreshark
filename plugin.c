/*
 * Do not modify this file.
 *
 * It is created automatically by Makefile or Makefile.nmake.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pyreshark.h"
#include <gmodule.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

G_MODULE_EXPORT void
plugin_register (void)
{
    init_pyreshark();
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
    handoff_pyreshark();
}
#endif
