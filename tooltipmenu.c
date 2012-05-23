/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
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

/* This file is based on a copy of gtkkmenutray.c  */


/*
 * Pidgin is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */
#include "debug.h"

#include "tooltipmenu.h"

#include <gtk/gtkeventbox.h>
#include <gtk/gtkiconfactory.h>
#include <gtk/gtkversion.h>

/******************************************************************************
 * Enums
 *****************************************************************************/
enum {
	PROP_ZERO = 0,
	PROP_BOX
};

/******************************************************************************
 * Globals
 *****************************************************************************/
static GObjectClass *parent_class = NULL;

/******************************************************************************
 * Internal Stuff
 *****************************************************************************/

/******************************************************************************
 * Item Stuff
 *****************************************************************************/
/*static void
tooltip_menu_select(GtkItem *item) {

}

static void
tooltip_menu_deselect(GtkItem *item) {

}*/

/******************************************************************************
 * Widget Stuff
 *****************************************************************************/

/******************************************************************************
 * Object Stuff
 *****************************************************************************/
static void
tooltip_menu_get_property(GObject *obj, guint param_id, GValue *value,
								GParamSpec *pspec)
{
	TooltipMenu *tooltip_menu = TOOLTIP_MENU(obj);

	switch(param_id) {
		case PROP_BOX:
			g_value_set_object(value, tooltip_menu_get_box(tooltip_menu));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(obj, param_id, pspec);
			break;
	}
}

static void
tooltip_menu_finalize(GObject *obj) {
#if 0
	/* This _might_ be leaking, but I have a sneaking suspicion that the widget is
	 * getting destroyed in GtkContainer's finalize function.  But if were are
	 * leaking here, be sure to figure out why this causes a crash.
	 *      -- Gary
	 */
	TooltipMenu *tray = TOOLTIP_MENU(obj);

	if(GTK_IS_WIDGET(tray->tray))
		gtk_widget_destroy(GTK_WIDGET(tray->tray));
#endif

	G_OBJECT_CLASS(parent_class)->finalize(obj);
}

static void
tooltip_menu_class_init(TooltipMenuClass *klass) {
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	GParamSpec *pspec;

	parent_class = g_type_class_peek_parent(klass);

	object_class->finalize = tooltip_menu_finalize;
	object_class->get_property = tooltip_menu_get_property;

	pspec = g_param_spec_object("box", "The box",
		"The box",
		GTK_TYPE_BOX,
		G_PARAM_READABLE);
	g_object_class_install_property(object_class, PROP_BOX, pspec);
}

static void
tooltip_menu_init(TooltipMenu *tooltip_menu) {
	GtkWidget *widget = GTK_WIDGET(tooltip_menu);
	gtk_menu_item_set_right_justified(GTK_MENU_ITEM(tooltip_menu), TRUE);

	if(!GTK_IS_WIDGET(tooltip_menu->tray))
		tooltip_menu->tray = gtk_hbox_new(FALSE, 0);

	tooltip_menu->tooltips = gtk_tooltips_new();

	gtk_widget_set_size_request(widget, -1, -1);

	gtk_container_add(GTK_CONTAINER(tooltip_menu), tooltip_menu->tray);

	gtk_widget_show(tooltip_menu->tray);
}

/******************************************************************************
 * API
 *****************************************************************************/
GType
tooltip_menu_get_gtype(void) {
	static GType type = 0;

	if(type == 0) {
		static const GTypeInfo info = {
			sizeof(TooltipMenuClass),
			NULL,
			NULL,
			(GClassInitFunc)tooltip_menu_class_init,
			NULL,
			NULL,
			sizeof(TooltipMenu),
			0,
			(GInstanceInitFunc)tooltip_menu_init,
			NULL
		};

		type = g_type_register_static(GTK_TYPE_MENU_ITEM,
									  "TooltipMenu",
									  &info, 0);
	}

	return type;
}

GtkWidget *
tooltip_menu_new() {
	return g_object_new(TYPE_TOOLTIP_MENU, NULL);
}

GtkWidget *
tooltip_menu_get_box(TooltipMenu *tooltip_menu) {
	g_return_val_if_fail(IS_TOOLTIP_MENU(tooltip_menu), NULL);
	return tooltip_menu->tray;
}

static void
tooltip_menu_add(TooltipMenu *tooltip_menu, GtkWidget *widget,
					   const char *tooltip, gboolean prepend)
{
	g_return_if_fail(IS_TOOLTIP_MENU(tooltip_menu));
	g_return_if_fail(GTK_IS_WIDGET(widget));

	if (GTK_WIDGET_NO_WINDOW(widget))
	{
		GtkWidget *event;

		event = gtk_event_box_new();
		gtk_container_add(GTK_CONTAINER(event), widget);
		gtk_widget_show(event);
		widget = event;
	}

	tooltip_menu_set_tooltip(tooltip_menu, widget, tooltip);

	if (prepend)
		gtk_box_pack_start(GTK_BOX(tooltip_menu->tray), widget, FALSE, FALSE, 0);
	else
		gtk_box_pack_end(GTK_BOX(tooltip_menu->tray), widget, FALSE, FALSE, 0);
}

void
tooltip_menu_append(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip)
{
	tooltip_menu_add(tooltip_menu, widget, tooltip, FALSE);
}

void
tooltip_menu_prepend(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip)
{
	tooltip_menu_add(tooltip_menu, widget, tooltip, TRUE);
}

void
tooltip_menu_set_tooltip(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip)
{
	if (!tooltip_menu->tooltips)
		return;

	/* Should we check whether widget is a child of tooltip_menu? */

	/*
	 * If the widget does not have it's own window, then it
	 * must have automatically been added to an event box
	 * when it was added to the menu tray.  If this is the
	 * case, we want to set the tooltip on the widget's parent,
	 * not on the widget itself.
	 */
	if (GTK_WIDGET_NO_WINDOW(widget))
		widget = widget->parent;

	gtk_tooltips_set_tip(tooltip_menu->tooltips, widget, tooltip, NULL);
}

