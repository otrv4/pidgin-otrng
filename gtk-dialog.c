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
#include "gtkutils.h"
#include "gtkimhtml.h"
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

/* The OTR icons */

static const char * not_private_xpm[] = {
"26 24 3 1",
" 	c None",
".	c #000000",
"+	c #FF0000",
"      ..            ...   ",
"     .++.          .+++.  ",
"     .++.         ..++++. ",
"     .+++.       .++++++. ",
"     .++++.     .+++++++. ",
"      .++++.   .++++++++. ",
"      .+++++. .+++++++++. ",
"       .+++++..++++++++.  ",
"        .+++++.+++++++.   ",
"        .++++++++++++.    ",
"        .+++++++++++.     ",
"         .+++++++++.      ",
"          .+++++++.       ",
"         .+++++++++.      ",
"        .+++++++++++.     ",
"       .+++++++++++++.    ",
"      .+++++++++++++++..  ",
"      .+++++++.+++++++++. ",
"     .++++++...++++++++++.",
"    .++++++.   .+++++++++.",
"   .++++++.     .++++++++.",
" ..++++++.       .+++++++.",
".+++++++.         .+++++. ",
" .......           .....  "};

static const char * unverified_xpm[] = {
"16 24 3 1",
" 	c None",
".	c #000000",
"+	c #FFFF00",
"   ........     ",
" ..++++++++..   ",
".++++++++++++.  ",
".++++...++++++. ",
".+++.   .++++++.",
".++.     .+++++.",
".++.     .+++++.",
" ..      .+++++.",
"         .+++++.",
"        .+++++. ",
"       ..+++++. ",
"      .++++++.  ",
"     .+++++..   ",
"     .++...     ",
"     .++.       ",
"     .++.       ",
"     ....       ",
"    .++++.      ",
"   .++++++.     ",
"   .++++++.     ",
"   .++++++.     ",
"   .++++++.     ",
"    .++++.      ",
"     ....       "};

static const char * private_xpm[] = {
"22 24 3 1",
" 	c None",
".	c #000000",
"+	c #00FF00",
"                    . ",
"                   .+.",
"                  .++.",
"                 .+++.",
"                .++++.",
"               .+++++.",
"              .++++++.",
"             .+++++++.",
"  ...       .+++++++. ",
" .+++.     .+++++++.  ",
".+++++.   .+++++++.   ",
".+++++.  .+++++++.    ",
".+++++. .+++++++.     ",
".+++++..+++++++.      ",
".+++++.+++++++.       ",
".++++++++++++.        ",
".+++++++++++.         ",
".++++++++++.          ",
".+++++++++.           ",
".++++++++.            ",
".+++++++.             ",
".++++++.              ",
" .++++.               ",
"  ....                "};

static const char * finished_xpm[] = {
"24 24 4 1",
" 	c None",
".	c #000000",
"+	c #FF0000",
"@	c #FFFFFF",
"         ......         ",
"      ...++++++...      ",
"     .++++++++++++.     ",
"    .++++++++++++++.    ",
"   .++++++++++++++++.   ",
"  .++++++++++++++++++.  ",
" .++++++++++++++++++++. ",
" .++++++++++++++++++++. ",
" .++++++++++++++++++++. ",
".++++++++++++++++++++++.",
".++@@@@@@@@@@@@@@@@@@++.",
".++@@@@@@@@@@@@@@@@@@++.",
".++@@@@@@@@@@@@@@@@@@++.",
".++@@@@@@@@@@@@@@@@@@++.",
".++++++++++++++++++++++.",
" .++++++++++++++++++++. ",
" .++++++++++++++++++++. ",
" .++++++++++++++++++++. ",
"  .++++++++++++++++++.  ",
"   .++++++++++++++++.   ",
"    .++++++++++++++.    ",
"     .++++++++++++.     ",
"      ...++++++...      ",
"         ......         "};

static GtkWidget *otr_icon(GtkWidget *image, TrustLevel level)
{
    GdkPixbuf *pixbuf = NULL;
    const char **data = NULL;

    switch(level) {
	case TRUST_NOT_PRIVATE:
	    data = not_private_xpm;
	    break;
	case TRUST_UNVERIFIED:
	    data = unverified_xpm;
	    break;
	case TRUST_PRIVATE:
	    data = private_xpm;
	    break;
	case TRUST_FINISHED:
	    data = finished_xpm;
	    break;
    }

    pixbuf = gdk_pixbuf_new_from_xpm_data(data);
    if (image) {
	gtk_image_set_from_pixbuf(GTK_IMAGE(image), pixbuf);
    } else {
	image = gtk_image_new_from_pixbuf(pixbuf);
    }
    gdk_pixbuf_unref(pixbuf);

    return image;
}

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget)
{
    gtk_widget_destroy(GTK_WIDGET(widget));
}

static GtkWidget *create_dialog(GaimNotifyMsgType type, const char *title,
	const char *primary, const char *secondary, int sensitive,
	GtkWidget **labelp, void (*add_custom)(GtkWidget *vbox, void *data),
	void *add_custom_data)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *vbox;
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
    vbox = gtk_vbox_new(FALSE, 0);
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
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    if (add_custom) {
	add_custom(vbox, add_custom_data);
    }
    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

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
    create_dialog(type, title, primary, secondary, 1, NULL, NULL, NULL);
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
	    0, &label, NULL, NULL);
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

/* Adds a "What's this?" expander to a vbox, containing { some "whatsthis"
 * markup (displayed in a GtkLabel) and a "More..." expander, containing
 * { some "more" markup (displayed in a GtkIMHTML) } }. */
static void add_whatsthis_more(GtkWidget *vbox, const char *whatsthismarkup,
	const char *moremarkup)
{
    GtkWidget *expander;
    GtkWidget *ebox;
    GtkWidget *whatsthis;
    GtkWidget *more;
    GtkWidget *frame;
    GtkWidget *scrl;
    GtkWidget *imh;
    GdkFont *font;

    expander = gtk_expander_new_with_mnemonic("_What's this?");
    gtk_box_pack_start(GTK_BOX(vbox), expander, FALSE, FALSE, 0);
    frame = gtk_frame_new(NULL);
    gtk_container_add(GTK_CONTAINER(expander), frame);
    ebox = gtk_vbox_new(FALSE, 10);
    gtk_container_add(GTK_CONTAINER(frame), ebox);
    whatsthis = gtk_label_new(NULL);
    gtk_label_set_line_wrap(GTK_LABEL(whatsthis), TRUE);
    gtk_label_set_markup(GTK_LABEL(whatsthis), whatsthismarkup);

    gtk_box_pack_start(GTK_BOX(ebox), whatsthis, FALSE, FALSE, 0);
    more = gtk_expander_new_with_mnemonic("_More...");
    gtk_box_pack_start(GTK_BOX(ebox), more, FALSE, FALSE, 0);
    scrl = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(more), scrl);

    imh = gtk_imhtml_new(NULL, NULL);
    gaim_setup_imhtml(imh);
    gtk_imhtml_append_text(GTK_IMHTML(imh), moremarkup, GTK_IMHTML_NO_SCROLL);

    gtk_container_add(GTK_CONTAINER(scrl), imh);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrl),
	    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    /* This is a deprecated API, but mucking with PangoFontDescriptions
     * is (a) complicated, and (b) not fully supported by older versions
     * of libpango, which some people may have. */
    font = gtk_style_get_font(imh->style);
    gtk_widget_set_size_request(scrl, -1, 6 * (font->ascent + font->descent));
}

static void add_unk_fingerprint_expander(GtkWidget *vbox, void *data)
{
    add_whatsthis_more(vbox,
	    "A <b>fingerprint</b> is a unique identifier that you should "
	    "use to authenticate your buddy.  Right-click on the OTR button "
	    "in your buddy's conversation window, and choose \"Verify "
	    "fingerprint\".",

	    "If your buddy has more than one IM account, or uses more than "
	    "one computer, he may have multiple fingerprints.\n\n"
	    "However, the only way an imposter could duplicate one of your "
	    "buddy's fingerprints is by stealing information from his "
	    "computer.\n\n"
	    "<a href=\"" FINGERPRINT_HELPURL "\">"
	    "Click here for more information about fingerprints.</a>");
}

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint.
 * Ask the user whether to accept the fingerprint or not.  If yes, call
 * response_cb(ops, opdata, response_data, resp) with resp = 1.  If no,
 * set resp = 0.  If the user destroys the dialog without answering, set
 * resp = -1. */
static void otrg_gtk_dialog_unknown_fingerprint(OtrlUserState us,
	const char *accountname, const char *protocol, const char *who,
	unsigned char fingerprint[20])
{
    char hash[45];
    char *primary, *secondary;
    GaimPlugin *p = gaim_find_prpl(protocol);
    
    otrl_privkey_hash_to_human(hash, fingerprint);
    primary = g_strdup_printf("%s (%s) has received an unknown fingerprint "
	    "from %s:", accountname, 
	    (p && p->info->name) ? p->info->name : "Unknown", who);
    secondary = g_strdup_printf("%s\n", hash);

    create_dialog(GAIM_NOTIFY_MSG_WARNING, "Unknown fingerprint",
	    primary, secondary, 1, NULL, add_unk_fingerprint_expander, NULL);

    g_free(primary);
    g_free(secondary);
}

static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void dialog_update_label_conv(GaimConversation *conv, TrustLevel level)
{
    GtkWidget *label;
    GtkWidget *icon;
    GtkWidget *icontext;
    GtkWidget *button;
    GtkWidget *menuquery;
    GtkWidget *menuend;
    GtkWidget *menuquerylabel;
    GtkWidget *menuview;
    GtkWidget *menuverf;
    GaimButtonStyle buttonstyle;
    GaimGtkConversation *gtkconv = GAIM_GTK_CONVERSATION(conv);
    label = gaim_conversation_get_data(conv, "otr-label");
    icon = gaim_conversation_get_data(conv, "otr-icon");
    icontext = gaim_conversation_get_data(conv, "otr-icontext");
    button = gaim_conversation_get_data(conv, "otr-button");
    menuquery = gaim_conversation_get_data(conv, "otr-menuquery");
    menuquerylabel = gtk_bin_get_child(GTK_BIN(menuquery));
    menuend = gaim_conversation_get_data(conv, "otr-menuend");
    menuview = gaim_conversation_get_data(conv, "otr-menuview");
    menuverf = gaim_conversation_get_data(conv, "otr-menuverf");
    buttonstyle = gaim_prefs_get_int("/gaim/gtk/conversations/button_type");

    /* Set the button's icon, label and tooltip. */
    otr_icon(icon, level);
    gtk_label_set_text(GTK_LABEL(label),
	    level == TRUST_FINISHED ? "Finished" :
	    level == TRUST_PRIVATE ? "Private" :
	    level == TRUST_UNVERIFIED ? "Unverified" :
	    "Not private");
    gtk_tooltips_set_tip(gtkconv->tooltips, button,
	    level == TRUST_NOT_PRIVATE ? "Start a private conversation" :
		    "Refresh the private conversation", NULL);

    /* Set the menu item label for the OTR Query item. */
    gtk_label_set_markup_with_mnemonic(GTK_LABEL(menuquerylabel),
	    level == TRUST_NOT_PRIVATE ? "Start _private conversation" :
		    "Refresh _private conversation");

    /* Sensitize the menu items as appropriate. */
    gtk_widget_set_sensitive(GTK_WIDGET(menuend), level != TRUST_NOT_PRIVATE);
    gtk_widget_set_sensitive(GTK_WIDGET(menuview), level != TRUST_NOT_PRIVATE);
    gtk_widget_set_sensitive(GTK_WIDGET(menuverf), level != TRUST_NOT_PRIVATE);

    /* Use any non-NULL value for "private", NULL for "not private" */
    gaim_conversation_set_data(conv, "otr-private",
	    level == TRUST_NOT_PRIVATE ? NULL : conv);

    /* Set the appropriate visibility */
    gtk_widget_show_all(button);
    if (buttonstyle == GAIM_BUTTON_IMAGE) {
	/* Hide the text */
	gtk_widget_hide(icontext);
	gtk_widget_hide(label);
    }
    if (buttonstyle == GAIM_BUTTON_TEXT) {
	/* Hide the icon */
	gtk_widget_hide(icontext);
	gtk_widget_hide(icon);
    }
}

static void dialog_update_label(ConnContext *context)
{
    GaimAccount *account;
    GaimConversation *conv;
    TrustLevel level = otrg_plugin_context_to_trust(context);

    account = gaim_accounts_find(context->accountname, context->protocol);
    if (!account) return;
    conv = gaim_find_conversation_with_account(context->username, account);
    if (!conv) return;
    dialog_update_label_conv(conv, level);
}

/* Add the help text for the "view session id" dialog. */
static void add_sessid_expander(GtkWidget *vbox, void *data)
{
    add_whatsthis_more(vbox,
	    "You can use this <b>secure session id</b> to double-check "
	    "the privacy of <i>this one conversation</i>.",

	    "To verify the session id, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your bold "
	    "half of the above session id to the other "
	    "(your buddy will have the same session id as you, but with the "
	    "other half bold).\n\nIf everything matches up, then <i>the "
	    "current conversation</i> between your computer and your buddy's "
	    "computer is private.\n\n"
	    "<b>Note:</b> You will probably never have to do this.  You "
	    "should normally use the \"Verify fingerprint\" functionality "
	    "instead.\n\n"
	    "<a href=\"" SESSIONID_HELPURL "\">"
	    "Click here for more information about the secure "
	    "session id.</a>");
}

static GtkWidget* otrg_gtk_dialog_view_sessionid(ConnContext *context)
{
    GtkWidget *dialog;
    unsigned char *sessionid;
    char sess1[21], sess2[21];
    char *primary = g_strdup_printf("Private connection with %s "
	    "established.", context->username);
    char *secondary;
    int i;
    OtrlSessionIdHalf whichhalf = context->sessionid_half;
    size_t idhalflen = (context->sessionid_len) / 2;

    /* Make a human-readable version of the sessionid (in two parts) */
    sessionid = context->sessionid;
    for(i=0;i<idhalflen;++i) sprintf(sess1+(2*i), "%02x", sessionid[i]);
    for(i=0;i<idhalflen;++i) sprintf(sess2+(2*i), "%02x",
	    sessionid[i+idhalflen]);
    
    secondary = g_strdup_printf("Secure session id:\n"
	    "<span %s>%s</span> <span %s>%s</span>\n",
	    whichhalf == OTRL_SESSIONID_FIRST_HALF_BOLD ?
		    "weight=\"bold\"" : "", sess1,
	    whichhalf == OTRL_SESSIONID_SECOND_HALF_BOLD ?
		    "weight=\"bold\"" : "", sess2);

    dialog = create_dialog(GAIM_NOTIFY_MSG_INFO, "Private connection "
	    "established", primary, secondary, 1, NULL,
	    add_sessid_expander, NULL);

    g_free(primary);
    g_free(secondary);

    return dialog;
}

struct vrfy_fingerprint_data {
    Fingerprint *fprint;   /* You can use this pointer right away, but
			      you can't rely on it sticking around for a
			      while.  Use the copied pieces below
			      instead. */
    char *accountname, *username, *protocol;
    unsigned char fingerprint[20];
};

static void vrfy_fingerprint_data_free(struct vrfy_fingerprint_data *vfd)
{
    free(vfd->accountname);
    free(vfd->username);
    free(vfd->protocol);
    free(vfd);
}

static struct vrfy_fingerprint_data* vrfy_fingerprint_data_new(
	Fingerprint *fprint)
{
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context = fprint->context;

    vfd = malloc(sizeof(*vfd));
    vfd->fprint = fprint;
    vfd->accountname = strdup(context->accountname);
    vfd->username = strdup(context->username);
    vfd->protocol = strdup(context->protocol);
    memmove(vfd->fingerprint, fprint->fingerprint, 20);

    return vfd;
}

static void vrfy_fingerprint_destroyed(GtkWidget *w,
	struct vrfy_fingerprint_data *vfd)
{
    vrfy_fingerprint_data_free(vfd);
}

static void vrfy_fingerprint_changed(GtkComboBox *combo, void *data)
{
    struct vrfy_fingerprint_data *vfd = data;
    ConnContext *context = otrl_context_find(otrg_plugin_userstate,
	    vfd->username, vfd->accountname, vfd->protocol, 0, NULL,
	    NULL, NULL);
    Fingerprint *fprint;
    int oldtrust, trust;

    if (context == NULL) return;

    fprint = otrl_context_find_fingerprint(context, vfd->fingerprint,
	    0, NULL);

    if (fprint == NULL) return;

    oldtrust = (fprint->trust && fprint->trust[0]);
    trust = gtk_combo_box_get_active(combo) == 1 ? 1 : 0;

    /* See if anything's changed */
    if (trust != oldtrust) {
	otrl_context_set_trust(fprint, trust ? "verified" : "");
	/* Write the new info to disk, redraw the ui, and redraw the
	 * OTR buttons. */
	otrg_plugin_write_fingerprints();
	otrg_ui_update_keylist();
	otrg_dialog_resensitize_all();
    }
}

/* Add the verify widget and the help text for the verify fingerprint box. */
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data)
{
    GtkWidget *hbox;
    GtkWidget *combo, *label;
    struct vrfy_fingerprint_data *vfd = data;
    char *labelt;
    int verified = 0;

    if (vfd->fprint->trust && vfd->fprint->trust[0]) {
	verified = 1;
    }

    hbox = gtk_hbox_new(FALSE, 0);
    combo = gtk_combo_box_new_text();
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), "I have not");
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), "I have");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), verified);
    label = gtk_label_new(" verified that this is in fact the correct");
    gtk_box_pack_start(GTK_BOX(hbox), combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    g_signal_connect(G_OBJECT(combo), "changed",
	    G_CALLBACK(vrfy_fingerprint_changed), vfd);

    hbox = gtk_hbox_new(FALSE, 0);
    labelt = g_strdup_printf("fingerprint for %s.",
	    vfd->username);
    label = gtk_label_new(labelt);
    g_free(labelt);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);

    add_whatsthis_more(vbox,
	    "A <b>fingerprint</b> is a unique identifier that you should "
	    "use to authenticate your buddy.",

	    "To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other.\n\n"
	    "If everything matches up, you should indicate in the above "
	    "dialog that you <b>have</b> verified the fingerprint.\n\n"
	    "If your buddy has more than one IM account, or uses more than "
	    "one computer, he may have multiple fingerprints.\n\n"
	    "However, the only way an imposter could duplicate one of your "
	    "buddy's fingerprints is by stealing information from his "
	    "computer.\n\n"
	    "<a href=\"" FINGERPRINT_HELPURL "\">"
	    "Click here for more information about fingerprints.</a>");
}

static void otrg_gtk_dialog_verify_fingerprint(Fingerprint *fprint)
{
    GtkWidget *dialog;
    char our_hash[45], their_hash[45];
    char *primary;
    char *secondary;
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context;
    GaimPlugin *p;
    char *proto_name;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;
    context = fprint->context;
    if (context == NULL) return;

    primary = g_strdup_printf("Verify fingerprint for %s",
	    context->username);
    vfd = vrfy_fingerprint_data_new(fprint);

    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
	    context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = gaim_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : "Unknown";
    secondary = g_strdup_printf("Fingerprint for you, %s (%s):\n%s\n\n"
	    "Purported fingerprint for %s:\n%s\n", context->accountname,
	    proto_name, our_hash, context->username, their_hash);

    dialog = create_dialog(GAIM_NOTIFY_MSG_INFO, "Verify fingerprint",
	    primary, secondary, 1, NULL, add_vrfy_fingerprint, vfd);
    g_signal_connect(G_OBJECT(dialog), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);

    g_free(primary);
    g_free(secondary);
}

/* Call this when a context transitions to ENCRYPTED. */
static void otrg_gtk_dialog_connected(ConnContext *context)
{
    GaimConversation *conv;
    char *buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    buf = g_strdup_printf("%s conversation with %s started.%s",
		level == TRUST_PRIVATE ? "Private" :
		level == TRUST_UNVERIFIED ? "<a href=\"" UNVERIFIED_HELPURL
			"\">Unverified</a>" :
		    /* This last case should never happen, since we know
		     * we're in ENCRYPTED. */
		    "Not private",
		gaim_conversation_get_name(conv),
		context->protocol_version == 1 ? "  Warning: using old "
		    "protocol version 1." : "");

    gaim_conversation_write(conv, NULL, buf, GAIM_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
}

/* Call this when a context transitions to PLAINTEXT. */
static void otrg_gtk_dialog_disconnected(ConnContext *context)
{
    GaimConversation *conv;
    char *buf;

    conv = otrg_plugin_context_to_conv(context, 1);

    buf = g_strdup_printf("Private conversation with %s lost.",
	    gaim_conversation_get_name(conv));
    gaim_conversation_write(conv, NULL, buf, GAIM_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
static void otrg_gtk_dialog_finished(const char *accountname,
	const char *protocol, const char *username)
{
    /* See if there's a conversation window we can put this in. */
    GaimAccount *account;
    GaimConversation *conv;
    char *buf;

    account = gaim_accounts_find(accountname, protocol);
    if (!account) return;

    conv = gaim_find_conversation_with_account(username, account);
    if (!conv) return;

    buf = g_strdup_printf("%s has ended his private conversation with you; "
	    "you should do the same.", gaim_conversation_get_name(conv));
    gaim_conversation_write(conv, NULL, buf, GAIM_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label_conv(conv, TRUST_FINISHED);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrg_gtk_dialog_stillconnected(ConnContext *context)
{
    GaimConversation *conv;
    char *buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    buf = g_strdup_printf("Successfully refreshed the %s conversation "
		"with %s.%s",
		level == TRUST_PRIVATE ? "private" :
		level == TRUST_UNVERIFIED ? "<a href=\"" UNVERIFIED_HELPURL
			"\">unverified</a>" :
		    /* This last case should never happen, since we know
		     * we're in ENCRYPTED. */
		    "not private",
		gaim_conversation_get_name(conv),
		context->protocol_version == 1 ? "  Warning: using old "
		    "protocol version 1." : "");

    gaim_conversation_write(conv, NULL, buf, GAIM_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
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

static void view_sessionid(GtkWidget *widget, gpointer data)
{
    GaimConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_gtk_dialog_view_sessionid(context);
}

static void verify_fingerprint(GtkWidget *widget, gpointer data)
{
    GaimConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_gtk_dialog_verify_fingerprint(context->active_fingerprint);
}

static void menu_whatsthis(GtkWidget *widget, gpointer data)
{
    gaim_notify_uri(otrg_plugin_handle, BUTTON_HELPURL);
}

static void menu_end_private_conversation(GtkWidget *widget, gpointer data)
{
    GaimConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    otrg_ui_disconnect_connection(context);
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
    g_hash_table_remove(conv->data, "otr-icon");
    g_hash_table_remove(conv->data, "otr-icontext");
    g_hash_table_remove(conv->data, "otr-private");
    g_hash_table_remove(conv->data, "otr-menu");
    g_hash_table_remove(conv->data, "otr-menuquery");
    g_hash_table_remove(conv->data, "otr-menuend");
    g_hash_table_remove(conv->data, "otr-menuview");
    g_hash_table_remove(conv->data, "otr-menuverf");
}

/* Set up the per-conversation information display */
static void otrg_gtk_dialog_new_conv(GaimConversation *conv)
{
    GaimGtkConversation *gtkconv = GAIM_GTK_CONVERSATION(conv);
    ConnContext *context;
    GtkWidget *bbox;
    GtkWidget *button;
    GtkWidget *label;
    GtkWidget *bwbox;
    GtkWidget *bvbox;
    GtkWidget *iconbox;
    GtkWidget *icon;
    GtkWidget *icontext;
    GtkWidget *menu;
    GtkWidget *menuquery;
    GtkWidget *menuend;
    GtkWidget *menusep;
    GtkWidget *menuview;
    GtkWidget *menuverf;
    GtkWidget *whatsthis;

    /* Do nothing if this isn't an IM conversation */
    if (gaim_conversation_get_type(conv) != GAIM_CONV_IM) return;

    bbox = gtkconv->bbox;

    context = otrg_plugin_conv_to_context(conv);

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
	dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
	return;
    }

    /* Make the button */
    button = gtk_button_new();
    gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);

    bwbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(button), bwbox);
    bvbox = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bwbox), bvbox, TRUE, FALSE, 0);
    iconbox = gtk_hbox_new(FALSE, 3);
    gtk_box_pack_start(GTK_BOX(bvbox), iconbox, FALSE, FALSE, 0);
    label = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(bvbox), label, FALSE, FALSE, 0);
    icontext = gtk_label_new("OTR:");
    gtk_box_pack_start(GTK_BOX(iconbox), icontext, FALSE, FALSE, 0);
    icon = otr_icon(NULL, TRUST_NOT_PRIVATE);
    gtk_box_pack_start(GTK_BOX(iconbox), icon, TRUE, FALSE, 0);

    gtk_widget_show_all(button);

    /* Make the context menu */
    menu = gtk_menu_new();
    gtk_menu_set_title(GTK_MENU(menu), "OTR Messaging");

    menuquery = gtk_menu_item_new_with_mnemonic("");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuquery);
    gtk_widget_show(menuquery);

    menuend = gtk_menu_item_new_with_mnemonic("_End private conversation");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuend);
    gtk_widget_show(menuend);

    menusep = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_widget_show(menusep);

    menuverf = gtk_menu_item_new_with_mnemonic("_Verify fingerprint");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuverf);
    gtk_widget_show(menuverf);

    menuview = gtk_menu_item_new_with_mnemonic("View _secure session id");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuview);
    gtk_widget_show(menuview);

    menusep = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_widget_show(menusep);

    whatsthis = gtk_menu_item_new_with_mnemonic("_What's this?");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), whatsthis);
    gtk_widget_show(whatsthis);

    gaim_conversation_set_data(conv, "otr-label", label);
    gaim_conversation_set_data(conv, "otr-button", button);
    gaim_conversation_set_data(conv, "otr-icon", icon);
    gaim_conversation_set_data(conv, "otr-icontext", icontext);
    gaim_conversation_set_data(conv, "otr-menu", menu);
    gaim_conversation_set_data(conv, "otr-menuquery", menuquery);
    gaim_conversation_set_data(conv, "otr-menuend", menuend);
    gaim_conversation_set_data(conv, "otr-menuview", menuview);
    gaim_conversation_set_data(conv, "otr-menuverf", menuverf);
    gtk_signal_connect(GTK_OBJECT(menuquery), "activate",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    gtk_signal_connect(GTK_OBJECT(menuend), "activate",
	    GTK_SIGNAL_FUNC(menu_end_private_conversation), conv);
    gtk_signal_connect(GTK_OBJECT(menuverf), "activate",
	    GTK_SIGNAL_FUNC(verify_fingerprint), conv);
    gtk_signal_connect(GTK_OBJECT(menuview), "activate",
	    GTK_SIGNAL_FUNC(view_sessionid), conv);
    gtk_signal_connect(GTK_OBJECT(whatsthis), "activate",
	    GTK_SIGNAL_FUNC(menu_whatsthis), conv);
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    g_signal_connect(G_OBJECT(button), "destroy",
	    G_CALLBACK(button_destroyed), conv);
    g_signal_connect(G_OBJECT(button), "button-press-event",
	    G_CALLBACK(button_pressed), conv);

    dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
    dialog_resensitize(conv);
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
    otrg_gtk_dialog_verify_fingerprint,
    otrg_gtk_dialog_connected,
    otrg_gtk_dialog_disconnected,
    otrg_gtk_dialog_stillconnected,
    otrg_gtk_dialog_finished,
    otrg_gtk_dialog_resensitize_all,
    otrg_gtk_dialog_new_conv,
    otrg_gtk_dialog_remove_conv
};

/* Get the GTK dialog UI ops */
const OtrgDialogUiOps *otrg_gtk_dialog_get_ui_ops(void)
{
    return &gtk_dialog_ui_ops;
}
