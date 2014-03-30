/* plugin.c
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

/*
 * Do not Delete this file, it is no longer auto-created.
 */

/* The following two lines prevent redefinition of ssize_t on win64*/
#define _SSIZE_T_DEFINED
#define QT_VERSION

#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

#if VERSION_MINOR > 8
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#else
#define WS_DLL_PUBLIC_NOEXTERN G_MODULE_EXPORT
#endif

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_NOEXTERN const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_NOEXTERN void
plugin_register (void)
{
    {extern void init_pyreshark (void); init_pyreshark();}
}

WS_DLL_PUBLIC_NOEXTERN void
plugin_reg_handoff(void)
{
    {extern void handoff_pyreshark (void); handoff_pyreshark();}
}
#endif
