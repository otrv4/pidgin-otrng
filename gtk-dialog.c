/*
 *  Off-the-Record Messaging plugin for gaim
 *  Copyright (C) 2004-2005  Nikita Borisov and Ian Goldberg
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

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>

/* gcrypt headers */
#include <gcrypt.h>

/* gaim headers */
#include "stock.h"
#include "plugin.h"
#include "notify.h"
#include "gtkconv.h"
#include "util.h"

/* libotr headers */
#include <libotr/dh.h>
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

/* gaim-otr headers */
#include "otr-plugin.h"
#include "dialogs.h"
#include "ui.h"

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget)
{
    gtk_widget_destroy(GTK_WIDGET(widget));
}

static GtkWidget *create_dialog(GaimNotifyMsgType type, const char *title,
	const char *primary, const char *secondary, int sensitive,
	GtkWidget **labelp)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *label;
    GtkWidget *img = NULL;
    char *label_text;
    const char *icon_name = NULL;

    switch (type) {
	case GAIM_NOTIFY_MSG_ERROR:
	    icon_name = GAIM_STOCK_DIALOG_ERROR;
	    break;

	case GAIM_NOTIFY_MSG_WARNING:
	    icon_name = GAIM_STOCK_DIALOG_WARNING;
	    break;

	case GAIM_NOTIFY_MSG_INFO:
	    icon_name = GAIM_STOCK_DIALOG_INFO;
	    break;

	default:
	    icon_name = NULL;
	    break;
    }

    if (icon_name != NULL) {
	img = gtk_image_new_from_stock(icon_name, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    }

    dialog = gtk_dialog_new_with_buttons(title ? title : GAIM_ALERT_TITLE,
					 NULL, 0, GTK_STOCK_OK,
					 GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT,
	    sensitive);

    gtk_window_set_accept_focus(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    g_signal_connect(G_OBJECT(dialog), "response",
				     G_CALLBACK(message_response_cb), dialog);

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    if (img != NULL) {
	gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);
    }

    label_text = g_strdup_printf(
		       "<span weight=\"bold\" size=\"larger\">%s</span>%s%s",
		       (primary ? primary : ""),
		       (primary ? "\n\n" : ""),
		       (secondary ? secondary : ""));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    gtk_widget_show_all(dialog);

    if (labelp) *labelp = label;
    return dialog;
}

/* This is just like gaim_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
static void otrg_gtk_dialog_notify_message(GaimNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    create_dialog(type, title, primary, secondary, 1, NULL);
}

struct s_OtrgDialogWait {
    GtkWidget *dialog;
    GtkWidget *label;
};

/* Put up a Please Wait dialog, with the "OK" button desensitized.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
static OtrgDialogWaitHandle otrg_gtk_dialog_private_key_wait_start(
	const char *account, const char *protocol)
{
    GaimPlugin *p;
    const char *title = "Generating private key";
    const char *primary = "Please wait";
    char *secondary;
    const char *protocol_print;
    GtkWidget *label;
    GtkWidget *dialog;
    OtrgDialogWaitHandle handle;

    p = gaim_find_prpl(protocol);
    protocol_print = (p ? p->info->name : "Unknown");
	
    /* Create the Please Wait... dialog */
    secondary = g_strdup_printf("Generating private key for %s (%s)...",
	    account, protocol_print);
	
    dialog = create_dialog(GAIM_NOTIFY_MSG_INFO, title, primary, secondary,
	    0, &label);
    handle = malloc(sizeof(struct s_OtrgDialogWait));
    handle->dialog = dialog;
    handle->label = label;

    /* Make sure the dialog is actually displayed before doing any
     * compute-intensive stuff. */
    while (gtk_events_pending ()) {
	gtk_main_iteration ();
    }
	
    g_free(secondary);

    return handle;
}

static int otrg_gtk_dialog_display_otr_message(const char *accountname,
	const char *protocol, const char *username, const char *msg)
{
    /* See if there's a conversation window we can put this in. */
    GaimAccount *account;
    GaimConversation *conv;

    account = gaim_accounts_find(accountname, protocol);
    if (!account) return -1;

    conv = gaim_find_conversation_with_account(username, account);
    if (!conv) return -1;

    gaim_conversation_write(conv, NULL, msg, GAIM_MESSAGE_SYSTEM, time(NULL));

    return 0;
}

/* End a Please Wait dialog. */
static void otrg_gtk_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    const char *oldmarkup;
    char *newmarkup;

    oldmarkup = gtk_label_get_label(GTK_LABEL(handle->label));
    newmarkup = g_strdup_printf("%s Done.", oldmarkup);

    gtk_label_set_markup(GTK_LABEL(handle->label), newmarkup);
    gtk_widget_show(handle->label);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(handle->dialog),
	    GTK_RESPONSE_ACCEPT, 1);

    g_free(newmarkup);
    free(handle);
}

struct ufcbdata {
    GtkDialog *dialog;
    void (*response_cb)(OtrlUserState us, OtrlMessageAppOps *ops, void *opdata,
	    OTRConfirmResponse *response_data, int resp);
    OtrlUserState us;
    OtrlMessageAppOps *ops;
    void *opdata;
    OTRConfirmResponse *response_data;
    int response;
};

static void unknown_fingerprint_destroy(GtkWidget *w, struct ufcbdata *cbdata)
{
    if (cbdata->response_cb) {
	cbdata->response_cb(cbdata->us, cbdata->ops, cbdata->opdata,
		cbdata->response_data, cbdata->response);
    }
    free(cbdata);
}

static void unknown_fingerprint_response(GtkWidget *w, int resp,
	struct ufcbdata *cbdata)
{
    if (resp == GTK_RESPONSE_OK) {
	cbdata->response = 1;
    } else if (resp == GTK_RESPONSE_CANCEL) {
	cbdata->response = 0;
    }
    gtk_widget_destroy(GTK_WIDGET(cbdata->dialog));
}

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint.
 * Ask the user whether to accept the fingerprint or not.  If yes, call
 * response_cb(ops, opdata, response_data, resp) with resp = 1.  If no,
 * set resp = 0.  If the user destroys the dialog without answering, set
 * resp = -1. */
static void otrg_gtk_dialog_unknown_fingerprint(OtrlUserState us,
	const char *accountname, const char *protocol, const char *who,
	OTRKeyExchangeMsg kem,
	void (*response_cb)(OtrlUserState us, OtrlMessageAppOps *ops,
	    void *opdata, OTRConfirmResponse *response_data, int resp),
	OtrlMessageAppOps *ops, void *opdata,
	OTRConfirmResponse *response_data)
{
    char hash[45];
    GtkWidget *img;
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *label;
    char *label_text;
    struct ufcbdata *cbd = malloc(sizeof(struct ufcbdata));
    const char *icon_name = GAIM_STOCK_DIALOG_WARNING;
    GaimPlugin *p = gaim_find_prpl(protocol);
    
    img = gtk_image_new_from_stock(icon_name, GTK_ICON_SIZE_DIALOG);
    gtk_misc_set_alignment(GTK_MISC(img), 0, 0);

    dialog = gtk_dialog_new_with_buttons( "Unknown Fingerprint",
	    NULL, GTK_DIALOG_NO_SEPARATOR, GTK_STOCK_OK, GTK_RESPONSE_OK,
	    GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);

    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    if (img != NULL)
	gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);

    otrl_privkey_hash_to_human(hash, kem->key_fingerprint);
    label_text = g_strdup_printf("<span weight=\"bold\" size=\"larger\">%s "
	    "(%s) has received an unknown fingerprint from %s:</span>\n\n"
	    "%s\n\n"
	    "Do you want to accept this fingerprint as valid?", accountname,
	    (p && p->info->name) ? p->info->name : "Unknown", who, hash);

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    g_free(label_text);

    cbd->dialog = GTK_DIALOG(dialog);
    cbd->response_cb = response_cb;
    cbd->us = us;
    cbd->ops = ops;
    cbd->opdata = opdata;
    cbd->response_data = response_data;
    cbd->response = -1;
    g_signal_connect(G_OBJECT(dialog), "destroy",
	    G_CALLBACK(unknown_fingerprint_destroy), cbd);
    g_signal_connect(G_OBJECT(dialog), "response",
	    G_CALLBACK(unknown_fingerprint_response), cbd);

    gtk_widget_show_all(dialog);
}

static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void dialog_update_label_conv(GaimConversation *conv, int is_private)
{
    GtkWidget *label;
    GtkWidget *button;
    GtkWidget *menuitem;
    GtkWidget *menuitemlabel;
    GaimGtkConversation *gtkconv = GAIM_GTK_CONVERSATION(conv);
    label = gaim_conversation_get_data(conv, "otr-label");
    button = gaim_conversation_get_data(conv, "otr-button");
    menuitem = gaim_conversation_get_data(conv, "otr-menuitem");
    menuitemlabel = gtk_bin_get_child(GTK_BIN(menuitem));

    /* Set the button's label and tooltip. */
    gtk_label_set_text(GTK_LABEL(label),
	    is_private ? "OTR:\nPrivate" : "OTR:\nNot private");
    gtk_tooltips_set_tip(gtkconv->tooltips, button,
	    is_private ? "Refresh the private conversation"
		       : "Start a private conversation", NULL);

    /* Set the menu item label. */
    gtk_label_set_markup_with_mnemonic(GTK_LABEL(menuitemlabel),
	    is_private ? "Refresh _private conversation"
		       : "Start _private conversation");

    /* Use any non-NULL value for "private", NULL for "not private" */
    gaim_conversation_set_data(conv, "otr-private",
	    is_private ? conv : NULL);
}

static void dialog_update_label(ConnContext *context, int is_private)
{
    GaimAccount *account;
    GaimConversation *conv;

    account = gaim_accounts_find(context->accountname, context->protocol);
    if (!account) return;
    conv = gaim_find_conversation_with_account(context->username, account);
    if (!conv) return;
    dialog_update_label_conv(conv, is_private);
}

/* Call this when a context transitions from (a state other than
 * CONN_CONNECTED) to CONN_CONNECTED. */
static void otrg_gtk_dialog_connected(ConnContext *context)
{
    char fingerprint[45];
    unsigned char *sessionid;
    char sess1[21], sess2[21];
    char *primary = g_strdup_printf("Private connection with %s "
	    "established.", context->username);
    char *secondary;
    int i;
    SessionDirection dir = context->sesskeys[1][0].dir;

    /* Make a human-readable version of the fingerprint */
    otrl_privkey_hash_to_human(fingerprint,
	    context->active_fingerprint->fingerprint);
    /* Make a human-readable version of the sessionid (in two parts) */
    sessionid = context->sesskeys[1][0].sessionid;
    for(i=0;i<10;++i) sprintf(sess1+(2*i), "%02x", sessionid[i]);
    sess1[20] = '\0';
    for(i=0;i<10;++i) sprintf(sess2+(2*i), "%02x", sessionid[i+10]);
    sess2[20] = '\0';
    
    secondary = g_strdup_printf("Fingerprint for %s:\n%s\n\n"
	    "Secure id for this session:\n"
	    "<span %s>%s</span> <span %s>%s</span>", context->username,
	    fingerprint,
	    dir == SESS_DIR_LOW ? "weight=\"bold\"" : "", sess1,
	    dir == SESS_DIR_HIGH ? "weight=\"bold\"" : "", sess2);

    otrg_dialog_notify_info(context->accountname, context->protocol,
	    context->username, "Private connection established",
	    primary, secondary);

    g_free(primary);
    g_free(secondary);
    dialog_update_label(context, 1);
}

/* Call this when a context transitions from CONN_CONNECTED to
 * (a state other than CONN_CONNECTED). */
static void otrg_gtk_dialog_disconnected(ConnContext *context)
{
    char *primary = g_strdup_printf("Private connection with %s lost.",
	    context->username);
    otrg_dialog_notify_warning(context->accountname, context->protocol,
	    context->username, "Private connection lost", primary, NULL);
    g_free(primary);
    dialog_update_label(context, 0);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrg_gtk_dialog_stillconnected(ConnContext *context)
{
    char *secondary = g_strdup_printf("<span size=\"larger\">Successfully "
	    "refreshed private connection with %s.</span>", context->username);
    otrg_dialog_notify_info(context->accountname, context->protocol,
	    context->username, "Refreshed private connection", NULL,
	    secondary);
    g_free(secondary);
    dialog_update_label(context, 1);
}

/* This is called when the OTR button in the button box is clicked, or
 * when the appropriate context menu item is selected. */
static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data)
{
    const char *format;
    char *buf;
    GaimConversation *conv = data;

    if (gaim_conversation_get_data(conv, "otr-private")) {
	format = "Attempting to refresh the private conversation with %s...";
    } else {
	format = "Attempting to start a private conversation with %s...";
    }
    buf = g_strdup_printf(format, gaim_conversation_get_name(conv));
    gaim_conversation_write(conv, NULL, buf, GAIM_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);
	
    otrg_plugin_send_default_query_conv(conv);
}

static void dialog_resensitize(GaimConversation *conv);

/* If the OTR button is right-clicked, show the context menu. */
static gboolean button_pressed(GtkWidget *w, GdkEventButton *event,
	gpointer data)
{
    GaimConversation *conv = data;

    if ((event->button == 3) && (event->type == GDK_BUTTON_PRESS)) {
	GtkWidget *menu = gaim_conversation_get_data(conv, "otr-menu");
	if (menu) {
	    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
		    3, event->time);
	    return TRUE;
	}
    }
    return FALSE;
}

/* If the OTR button gets destroyed on us, clean up the data we stored
 * pointing to it. */
static void button_destroyed(GtkWidget *w, GaimConversation *conv)
{
    GtkWidget *menu = gaim_conversation_get_data(conv, "otr-menu");
    if (menu) gtk_object_destroy(GTK_OBJECT(menu));
    g_hash_table_remove(conv->data, "otr-label");
    g_hash_table_remove(conv->data, "otr-button");
    g_hash_table_remove(conv->data, "otr-private");
    g_hash_table_remove(conv->data, "otr-menu");
    g_hash_table_remove(conv->data, "otr-menuitem");
}

/* Set up the per-conversation information display */
static void otrg_gtk_dialog_new_conv(GaimConversation *conv)
{
    GaimGtkConversation *gtkconv = GAIM_GTK_CONVERSATION(conv);
    GaimAccount *account;
    char *username;
    const char *accountname, *proto;
    ConnContext *context;
    ConnectionState state;
    GtkWidget *bbox;
    GtkWidget *button;
    GtkWidget *label;
    GtkWidget *menu;
    GtkWidget *menuitem;

    /* Do nothing if this isn't an IM conversation */
    if (gaim_conversation_get_type(conv) != GAIM_CONV_IM) return;

    bbox = gtkconv->bbox;

    /* See if we're already set up */
    button = gaim_conversation_get_data(conv, "otr-button");
    if (button) {
	/* Check if we've been removed from the bbox; gaim does this
	 * when the user changes her prefs for the style of buttons to
	 * display. */
	GList *children = gtk_container_get_children(GTK_CONTAINER(bbox));
	if (!g_list_find(children, button)) {
	    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
	}
	g_list_free(children);
	return;
    }

    account = gaim_conversation_get_account(conv);
    accountname = gaim_account_get_username(account);
    proto = gaim_account_get_protocol_id(account);
    username = g_strdup(
	    gaim_normalize(account, gaim_conversation_get_name(conv)));

    context = otrl_context_find(otrg_plugin_userstate, username, accountname,
	    proto, 0, NULL, NULL, NULL);
    state = context ? context->state : CONN_UNCONNECTED;
    g_free(username);

    button = gtk_button_new();
    label = gtk_label_new(NULL);
    gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    gtk_container_add(GTK_CONTAINER(button), label);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);

    /* Make the context menu */
    menu = gtk_menu_new();
    gtk_menu_set_title(GTK_MENU(menu), "OTR Messaging");

    menuitem = gtk_menu_item_new_with_mnemonic("");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);
    gtk_widget_show(menuitem);

    gaim_conversation_set_data(conv, "otr-label", label);
    gaim_conversation_set_data(conv, "otr-button", button);
    gaim_conversation_set_data(conv, "otr-menu", menu);
    gaim_conversation_set_data(conv, "otr-menuitem", menuitem);
    gtk_signal_connect(GTK_OBJECT(menuitem), "activate",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    g_signal_connect(G_OBJECT(button), "destroy",
	    G_CALLBACK(button_destroyed), conv);
    g_signal_connect(G_OBJECT(button), "button-press-event",
	    G_CALLBACK(button_pressed), conv);

    dialog_update_label_conv(conv, state == CONN_CONNECTED);
    dialog_resensitize(conv);
    gtk_widget_show_all(button);
}

/* Remove the per-conversation information display */
static void otrg_gtk_dialog_remove_conv(GaimConversation *conv)
{
    GtkWidget *button;

    /* Do nothing if this isn't an IM conversation */
    if (gaim_conversation_get_type(conv) != GAIM_CONV_IM) return;

    button = gaim_conversation_get_data(conv, "otr-button");
    if (button) gtk_object_destroy(GTK_OBJECT(button));
}

/* Set the OTR button to "sensitive" or "insensitive" as appropriate. */
static void dialog_resensitize(GaimConversation *conv)
{
    GaimAccount *account;
    GaimConnection *connection;
    GtkWidget *button;
    const char *name;
    OtrlPolicy policy;

    /* Do nothing if this isn't an IM conversation */
    if (gaim_conversation_get_type(conv) != GAIM_CONV_IM) return;

    account = gaim_conversation_get_account(conv);
    name = gaim_conversation_get_name(conv);
    policy = otrg_ui_find_policy(account, name);

    if (policy == OTRL_POLICY_NEVER) {
	otrg_gtk_dialog_remove_conv(conv);
    } else {
	otrg_gtk_dialog_new_conv(conv);
    }
    button = gaim_conversation_get_data(conv, "otr-button");
    if (!button) return;
    if (account) {
	connection = gaim_account_get_connection(account);
	if (connection) {
	    /* Set the button to "sensitive" */
	    gtk_widget_set_sensitive(button, 1);
	    return;
	}
    }
    /* Set the button to "insensitive" */
    gtk_widget_set_sensitive(button, 0);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
static void otrg_gtk_dialog_resensitize_all(void)
{
    gaim_conversation_foreach(dialog_resensitize);
}

static const OtrgDialogUiOps gtk_dialog_ui_ops = {
    otrg_gtk_dialog_notify_message,
    otrg_gtk_dialog_display_otr_message,
    otrg_gtk_dialog_private_key_wait_start,
    otrg_gtk_dialog_private_key_wait_done,
    otrg_gtk_dialog_unknown_fingerprint,
    otrg_gtk_dialog_connected,
    otrg_gtk_dialog_disconnected,
    otrg_gtk_dialog_stillconnected,
    otrg_gtk_dialog_resensitize_all,
    otrg_gtk_dialog_new_conv,
    otrg_gtk_dialog_remove_conv
};

/* Get the GTK dialog UI ops */
const OtrgDialogUiOps *otrg_gtk_dialog_get_ui_ops(void)
{
    return &gtk_dialog_ui_ops;
}
