/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2014  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Lisa Du, Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "otrng-plugin.h"

#include "dialogs.h"
#include "i18n.h"
#include "ui.h"

#ifdef USING_GTK
/* purple GTK headers */
#include "gtkplugin.h"

#include "gtk-dialog.h"
#include "gtk-ui.h"

static PidginPluginUiInfo ui_info = {otrng_gtk_ui_make_widget};

#define UI_INFO &ui_info
#define PLUGIN_TYPE PIDGIN_PLUGIN_TYPE

#else

#define UI_INFO NULL
#define PLUGIN_TYPE ""

#endif

static PurplePluginInfo otrng_plugin_info = {
    PURPLE_PLUGIN_MAGIC,

    /* Use the 2.0.x API */
    2, /* major version  */
    0, /* minor version  */

    PURPLE_PLUGIN_STANDARD,  /* type           */
    PLUGIN_TYPE,             /* ui_requirement */
    0,                       /* flags          */
    NULL,                    /* dependencies   */
    PURPLE_PRIORITY_DEFAULT, /* priority       */
    "otrng",                 /* id             */
    NULL,                    /* name           */
    PIDGIN_OTR_VERSION,      /* version        */
    NULL,                    /* summary        */
    NULL,                    /* description    */
                             /* author         */
    "Ian Goldberg, Rob Smits,\n"
    "\t\t\tChris Alexander, Willy Lew, Lisa Du,\n"
    "\t\t\tNikita Borisov <otr@cypherpunks.ca>",
    "https://otr.cypherpunks.ca/", /* homepage       */

    otrng_plugin_load,   /* load           */
    otrng_plugin_unload, /* unload         */
    NULL,                /* destroy        */

    UI_INFO, /* ui_info        */
    NULL,    /* extra_info     */
    NULL,    /* prefs_info     */
    NULL     /* actions        */
};

static void __otrng_init_plugin(PurplePlugin *plugin) {
/* Set up the UI ops */
#ifdef USING_GTK
  otrng_ui_set_ui_ops(otrng_gtk_ui_get_ui_ops());
  otrng_dialog_set_ui_ops(otrng_gtk_dialog_get_ui_ops());
#endif

#ifndef WIN32
  /* Make key generation use /dev/urandom instead of /dev/random */
  gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
#endif

  /* Initialize the OTR library */
  OTRNG_INIT;

#ifdef ENABLE_NLS
  bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
  bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif

  otrng_plugin_info.name = _("Off-the-Record Messaging nextgen");
  otrng_plugin_info.summary = _("Provides private and secure conversations");
  otrng_plugin_info.description =
      _("Preserves the privacy of IM communications "
        "by providing encryption, authentication, "
        "deniability, and perfect forward secrecy.");
}

PURPLE_INIT_PLUGIN(otrng, __otrng_init_plugin, otrng_plugin_info)
