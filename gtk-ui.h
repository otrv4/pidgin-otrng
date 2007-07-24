/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2007  Ian Goldberg, Chris Alexander, Nikita Borisov
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __OTRG_GTK_UI_H__
#define __OTRG_GTK_UI_H__

/* Construct the GTK OTR UI widget */
GtkWidget* otrg_gtk_ui_make_widget(PurplePlugin *plugin);

/* Get the GTK UI ops */
const OtrgUiUiOps *otrg_gtk_ui_get_ui_ops(void);

#endif
