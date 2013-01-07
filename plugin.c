/* plugin.c
 *
 * Pyreshark Plugin for Wireshark. (https://github.com/pyreshark/PyreShark)
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
