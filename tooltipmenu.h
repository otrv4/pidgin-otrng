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

/* This file is based on a copy of gtkkmenutray.h  */

/* Pidgin is the legal property of its developers, whose names are too numerous
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
#ifndef TOOLTIP_MENU_H
#define TOOLTIP_MENU_H

#include <gtk/gtkhbox.h>
#include <gtk/gtkmenuitem.h>
#include <gtk/gtktooltips.h>

#define TYPE_TOOLTIP_MENU                           (tooltip_menu_get_gtype())
#define TOOLTIP_MENU(obj)                           (GTK_CHECK_CAST((obj), TYPE_TOOLTIP_MENU, TooltipMenu))
#define TOOLTIP_MENU_CLASS(klass)           (GTK_CHECK_CLASS_CAST((klass), TYPE_TOOLTIP_MENU, TooltipMenuClass))
#define IS_TOOLTIP_MENU(obj)                        (GTK_CHECK_TYPE((obj), TYPE_TOOLTIP_MENU))
#define IS_TOOLTIP_MENU_CLASS(klass)        (GTK_CHECK_CLASS_TYPE((klass), TYPE_TOOLTIP_MENU))
#define TOOLTIP_MENU_GET_CLASS(obj) (GTK_CHECK_GET_CLASS((obj), TYPE_TOOLTIP_MENU, TooltipMenuClass))

typedef struct _TooltipMenu                          TooltipMenu;
typedef struct _TooltipMenuClass             TooltipMenuClass;

struct _TooltipMenu {
	GtkMenuItem gparent;                                    /**< The parent instance */
	GtkWidget *tray;                                                /**< The tray */
	GtkTooltips *tooltips;                                  /**< Tooltips */
};

struct _TooltipMenuClass {
	GtkMenuItemClass gparent;                               /**< The parent class */
};

G_BEGIN_DECLS

/**
 * Registers the TooltipMenu class if necessary and returns the
 * type ID assigned to it.
 *
 * @return The TooltipMenu type ID
 */
GType tooltip_menu_get_gtype(void);

/**
 * Creates a new TooltipMenu
 *
 * @return A new TooltipMenu
 */
GtkWidget *tooltip_menu_new(void);

/**
 * Gets the box for the TooltipMenu
 *
 * @param tooltip_menu The TooltipMenu
 *
 * @return The box that this menu tray is using
 */
GtkWidget *tooltip_menu_get_box(TooltipMenu *tooltip_menu);

/**
 * Appends a widget into the tray
 *
 * @param tooltip_menu The tray
 * @param widget    The widget
 * @param tooltip   The tooltip for this widget (widget requires its own X-window)
 */
void tooltip_menu_append(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip);

/**
 * Prepends a widget into the tray
 *
 * @param tooltip_menu The tray
 * @param widget    The widget
 * @param tooltip   The tooltip for this widget (widget requires its own X-window)
 */
void tooltip_menu_prepend(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip);

/**
 * Set the tooltip for a widget
 *
 * @param tooltip_menu The tray
 * @param widget    The widget
 * @param tooltip   The tooltip to set for the widget (widget requires its own X-window)
 */
void tooltip_menu_set_tooltip(TooltipMenu *tooltip_menu, GtkWidget *widget, const char *tooltip);

G_END_DECLS

#endif /* PIDGIN_MENU_TRAY_H */
