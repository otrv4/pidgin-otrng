/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
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

/* config.h */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>

/* gcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include "version.h"
#include "pidginstock.h"
#include "plugin.h"
#include "notify.h"
#include "gtkconv.h"
#include "gtkutils.h"
#include "gtkimhtml.h"
#include "util.h"
#include "core.h"
#include "gtkmenutray.h"
#include "tooltipmenu.h"

#ifdef ENABLE_NLS
/* internationalisation headers */
#include <glib/gi18n-lib.h>
#endif

/* libotr headers */
#include <libotr/dh.h>
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>
#include <libotr/instag.h>

/* purple-otr headers */
#include "otr-plugin.h"
#include "dialogs.h"
#include "gtk-dialog.h"
#include "ui.h"
#include "otr-icons.h"

static GHashTable * otr_win_menus = 0;
static GHashTable * otr_win_status = 0;

static int img_id_not_private = 0;
static int img_id_unverified = 0;
static int img_id_private = 0;
static int img_id_finished = 0;


typedef struct {
    ConnContext *context;       /* The context used to fire library code */
    GtkEntry* question_entry;   /* The text entry field containing the user
				 * question */
    GtkEntry *entry;	        /* The text entry field containing the secret */
    int smp_type;               /* Whether the SMP type is based on question
				 * challenge (0) or shared secret (1) */
    gboolean responder;	        /* Whether or not this is the first side to give
				 * their secret */
} SmpResponsePair;

/* Information used by the plugin that is specific to both the
 * application and connection. */
typedef struct dialog_context_data {
    GtkWidget       *smp_secret_dialog;
    SmpResponsePair *smp_secret_smppair;
    GtkWidget       *smp_progress_dialog;
    GtkWidget       *smp_progress_bar;
    GtkWidget       *smp_progress_label;
    otrl_instag_t   their_instance;
} SMPData;

typedef struct {
    SmpResponsePair *smppair;
    GtkEntry        *one_way_entry;
    GtkEntry        *two_way_entry;
    GtkWidget       *notebook;
} AuthSignalData;

typedef struct {
    enum {
	convctx_none,
	convctx_conv,
	convctx_ctx
    } convctx_type;
    PurpleConversation *conv;
    ConnContext *context;
} ConvOrContext;

static gint get_new_instance_index(PurpleConversation *conv)
{
    gint * max_index = (gint *)
	    purple_conversation_get_data(conv, "otr-max_idx");
    *max_index = (*max_index) + 1;
    return *max_index;
}

static gint get_context_instance_to_index(PurpleConversation *conv,
	ConnContext *context) {
    GHashTable * conv_to_idx_map =
	    purple_conversation_get_data(conv, "otr-conv_to_idx");
    gpointer index = NULL;

    if (!g_hash_table_lookup_extended(conv_to_idx_map, context, NULL, &index)) {
	index = g_malloc(sizeof(gint));
	*(gint *)index = get_new_instance_index(conv);
	g_hash_table_replace(conv_to_idx_map, context, index);
    }

    return *(gint *)index;
}

static void close_progress_window(SMPData *smp_data)
{
    if (smp_data->smp_progress_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_progress_dialog),
		GTK_RESPONSE_REJECT);
    }
    smp_data->smp_progress_dialog = NULL;
    smp_data->smp_progress_bar = NULL;
    smp_data->smp_progress_label = NULL;
}

static void otrg_gtk_dialog_free_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (!smp_data) return;

    if (smp_data->smp_secret_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_secret_dialog),
		GTK_RESPONSE_REJECT);
    }
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_secret_smppair = NULL;

    close_progress_window(smp_data);

    free(smp_data);

    g_hash_table_remove(conv->data, "otr-smpdata");
}

static void otrg_gtk_dialog_add_smp_data(PurpleConversation *conv)
{
    SMPData *smp_data = malloc(sizeof(SMPData));
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_secret_smppair = NULL;
    smp_data->smp_progress_dialog = NULL;
    smp_data->smp_progress_bar = NULL;
    smp_data->smp_progress_label = NULL;
    /* Chosen as initialized value since libotr should never allow
     * this as a "their_instance" value */
    smp_data->their_instance = OTRL_INSTAG_BEST;

    purple_conversation_set_data(conv, "otr-smpdata", smp_data);
}

static GtkWidget *otr_icon(GtkWidget *image, TrustLevel level,
	gboolean sensitivity)
{
    GdkPixbuf *pixbuf = NULL;
    const guint8 *data = NULL;

    switch(level) {
	case TRUST_NOT_PRIVATE:
	    data = not_private_pixbuf;
	    break;
	case TRUST_UNVERIFIED:
	    data = unverified_pixbuf;
	    break;
	case TRUST_PRIVATE:
	    data = private_pixbuf;
	    break;
	case TRUST_FINISHED:
	    data = finished_pixbuf;
	    break;
    }

    pixbuf = gdk_pixbuf_new_from_inline(-1, data, FALSE, NULL);
    if (image) {
	gtk_image_set_from_pixbuf(GTK_IMAGE(image), pixbuf);
    } else {
	image = gtk_image_new_from_pixbuf(pixbuf);
    }
    gdk_pixbuf_unref(pixbuf);

    gtk_widget_set_sensitive (image, sensitivity);

    return image;
}

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget)
{
    gtk_widget_destroy(GTK_WIDGET(widget));
}

/* Forward declarations for the benefit of smp_message_response_cb/redraw
 * authvbox */
static void verify_fingerprint(GtkWindow *parent, Fingerprint *fprint);
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data);
static struct vrfy_fingerprint_data* vrfy_fingerprint_data_new(
	Fingerprint *fprint);
static void vrfy_fingerprint_destroyed(GtkWidget *w,
	struct vrfy_fingerprint_data *vfd);
static void conversation_switched ( PurpleConversation *conv, void * data );

static GtkWidget *create_smp_progress_dialog(GtkWindow *parent,
	ConnContext *context);

/* Called when a button is pressed on the "progress bar" smp dialog */
static void smp_progress_response_cb(GtkDialog *dialog, gint response,
	ConnContext *context)
{
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    SMPData *smp_data = NULL;

    if (conv) {
	gdouble frac;

	smp_data = purple_conversation_get_data(conv, "otr-smpdata");
	frac = gtk_progress_bar_get_fraction(
		GTK_PROGRESS_BAR(smp_data->smp_progress_bar));

	if (frac != 0.0 && frac != 1.0 && response == GTK_RESPONSE_REJECT) {
	    otrg_plugin_abort_smp(context);
	}
    }
    /* In all cases, destroy the current window */
    gtk_widget_destroy(GTK_WIDGET(dialog));

    /* Clean up variables pointing to the destroyed objects */

    if (smp_data) {
	smp_data->smp_progress_bar = NULL;
	smp_data->smp_progress_label = NULL;
	smp_data->smp_progress_dialog = NULL;
    }
}

/* Called when a button is pressed on the "enter the secret" smp dialog
 * The data passed contains a pointer to the text entry field containing
 * the entered secret as well as the current context.
 */
static void smp_secret_response_cb(GtkDialog *dialog, gint response,
	AuthSignalData *auth_opt_data)
{
    ConnContext* context;
    PurpleConversation *conv;
    SMPData *smp_data;
    SmpResponsePair *smppair;

    if (!auth_opt_data) return;

    smppair = auth_opt_data->smppair;

    if (!smppair) return;

    context = smppair->context;

    if (response == GTK_RESPONSE_ACCEPT && smppair->entry) {
	GtkEntry* entry = smppair->entry;
	char *secret;
	size_t secret_len;

	GtkEntry* question_entry = smppair->question_entry;

	const char *user_question = NULL;


	if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
	    return;
	}

	secret = g_strdup(gtk_entry_get_text(entry));
	secret_len = strlen(secret);

	if (smppair->responder) {
	    otrg_plugin_continue_smp(context, (const unsigned char *)secret,
		    secret_len);

	} else {

	    if (smppair->smp_type == 0) {
		if (!question_entry) {
		    return;
		}

		user_question = gtk_entry_get_text(question_entry);

		if (user_question == NULL || strlen(user_question) == 0) {
		    return;
		}
	    }

	    /* pass user question here */
	    otrg_plugin_start_smp(context, user_question,
		    (const unsigned char *)secret, secret_len);

	}

	g_free(secret);

	/* launch progress bar window */
	create_smp_progress_dialog(GTK_WINDOW(dialog), context);
    } else if (response == GTK_RESPONSE_HELP) {
	char *helpurl = g_strdup_printf("%s%s&context=%s",
		AUTHENTICATE_HELPURL, _("?lang=en"),
		auth_opt_data->smppair->smp_type == 0 ?
		    ( /* Question and Answer */
		      auth_opt_data->smppair->responder ?
		      "answer" : "question" ) :
		auth_opt_data->smppair->smp_type == 1 ?
		    ( /* Shared secret */
		      auth_opt_data->smppair->responder ?
		      "secretresp" : "secret" ) :
		    /* Fingerprint */
		    "fingerprint"
		);
	purple_notify_uri(otrg_plugin_handle, helpurl);
	g_free(helpurl);

	/* Don't destroy the window */
	return;
    } else {
	otrg_plugin_abort_smp(context);
    }

    /* In all cases except HELP, destroy the current window */
    gtk_widget_destroy(GTK_WIDGET(dialog));

    /* Clean up references to this window */
    conv = otrg_plugin_context_to_conv(smppair->context, 0);
    smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    if (smp_data) {
	smp_data->smp_secret_dialog = NULL;
	smp_data->smp_secret_smppair = NULL;
    }

    /* Free memory */
    free(auth_opt_data);
    free(smppair);
}

static void close_smp_window(PurpleConversation *conv)
{
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (smp_data && smp_data->smp_secret_dialog) {
	gtk_dialog_response(GTK_DIALOG(smp_data->smp_secret_dialog),
		GTK_RESPONSE_REJECT);
    }
}

static GtkWidget *create_dialog(GtkWindow *parent,
	PurpleNotifyMsgType type, const char *title,
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
	case PURPLE_NOTIFY_MSG_ERROR:
	    icon_name = PIDGIN_STOCK_DIALOG_ERROR;
	    break;

	case PURPLE_NOTIFY_MSG_WARNING:
	    icon_name = PIDGIN_STOCK_DIALOG_WARNING;
	    break;

	case PURPLE_NOTIFY_MSG_INFO:
	    icon_name = PIDGIN_STOCK_DIALOG_INFO;
	    break;

	default:
	    icon_name = NULL;
	    break;
    }

    if (icon_name != NULL) {
	img = gtk_image_new_from_stock(icon_name,
		gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    }

    dialog = gtk_dialog_new_with_buttons(
	    title ? title : PIDGIN_ALERT_TITLE, parent, 0,
	    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);

    gtk_window_set_focus_on_map(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    g_signal_connect(G_OBJECT(dialog), "response",
	    G_CALLBACK(message_response_cb), dialog);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT,
	    sensitive);

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
    gtk_label_set_selectable(GTK_LABEL(label), 1);
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

static void add_to_vbox_init_one_way_auth(GtkWidget *vbox,
	ConnContext *context, AuthSignalData *auth_opt_data, char *question) {
    GtkWidget *question_entry;
    GtkWidget *entry;
    GtkWidget *label;
    GtkWidget *label2;
    char *label_text;

    SmpResponsePair* smppair = auth_opt_data->smppair;

    if (smppair->responder) {
	label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
	    _("Your buddy is attempting to determine if he or she is really "
		"talking to you, or if it's someone pretending to be you.  "
		"Your buddy has asked a question, indicated below.  "
		"To authenticate to your buddy, enter the answer and "
		"click OK."));
    } else {
	label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
	    _("To authenticate using a question, pick a question whose "
	    "answer is known only to you and your buddy.  Enter this "
	    "question and this answer, then wait for your buddy to "
	    "enter the answer too.  If the answers "
	    "don't match, then you may be talking to an imposter."));
    }

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);


    if (smppair->responder) {
	label_text = g_strdup_printf(_("This is the question asked by "
		"your buddy:"));
    } else {
	label_text = g_strdup_printf(_("Enter question here:"));
    }

    label = gtk_label_new(label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);



    if (smppair->responder && question) {
	label_text = g_markup_printf_escaped("<span background=\"white\" "
		"foreground=\"black\" weight=\"bold\">%s</span>", question);
	label = gtk_label_new(NULL);
	gtk_label_set_markup (GTK_LABEL(label), label_text);
	gtk_label_set_selectable(GTK_LABEL(label), FALSE);
	g_free(label_text);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	smppair->question_entry = NULL;
    } else {
	/* Create the text view where the user enters their question */
	question_entry = gtk_entry_new ();
	smppair->question_entry = GTK_ENTRY(question_entry);
	gtk_box_pack_start(GTK_BOX(vbox), question_entry, FALSE, FALSE, 0);
    }

    if (context->active_fingerprint->trust &&
	context->active_fingerprint->trust[0] && !(smppair->responder)) {
	label2 = gtk_label_new(_("This buddy is already authenticated."));
    } else {
	label2 = NULL;
    }


    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
	    FALSE, 0);

    label_text = g_strdup_printf(_("Enter secret answer here "
	    "(case sensitive):"));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    /* Create the text view where the user enters their secret */
    entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "");

    auth_opt_data->one_way_entry = GTK_ENTRY(entry);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), smppair->responder);

    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);

    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
	    FALSE, 0);

    if (label2) {
	gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
		FALSE, 0);
    }
}

static void add_to_vbox_init_two_way_auth(GtkWidget *vbox,
	ConnContext *context, AuthSignalData *auth_opt_data) {
    GtkWidget *entry;
    GtkWidget *label;
    GtkWidget *label2;
    char *label_text;

    label_text = g_strdup_printf("<small><i>\n%s\n</i></small>",
	_("To authenticate, pick a secret known "
	    "only to you and your buddy.  Enter this secret, then "
	    "wait for your buddy to enter it too.  If the secrets "
	    "don't match, then you may be talking to an imposter."));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    label_text = g_strdup_printf(_("Enter secret here:"));
    label = gtk_label_new(label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);


    /* Create the text view where the user enters their secret */
    entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(entry), "");
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    auth_opt_data->two_way_entry = GTK_ENTRY(entry);

    if (context->active_fingerprint->trust &&
	context->active_fingerprint->trust[0]) {
	label2 = gtk_label_new(_("This buddy is already authenticated."));
    } else {
	label2 = NULL;
    }

    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);

    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
	FALSE, 0);

    if (label2) {
	gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE,
		FALSE, 0);
    }
}

static void add_to_vbox_verify_fingerprint(GtkWidget *vbox,
	ConnContext *context, SmpResponsePair* smppair) {
    char our_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN],
	    their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
    GtkWidget *label;
    char *label_text;
    struct vrfy_fingerprint_data *vfd;
    PurplePlugin *p;
    char *proto_name;
    Fingerprint *fprint = context->active_fingerprint;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;

    label_text = g_strdup_printf("<small><i>\n%s %s\n</i></small>",
	    _("To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other."),
	    _("If everything matches up, you should chose <b>I have</b> "
	    "in the menu below."));
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    vfd = vrfy_fingerprint_data_new(fprint);

    strncpy(our_hash, _("[none]"), 44);
    our_hash[44] = '\0';
    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
	    context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");
    label_text = g_strdup_printf(_("Fingerprint for you, %s (%s):\n%s\n\n"
	    "Purported fingerprint for %s:\n%s\n"), context->accountname,
	    proto_name, our_hash, context->username, their_hash);

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    /* Make the label containing the fingerprints selectable, but
     * not auto-selected. */
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    g_object_set(label, "can-focus", FALSE, NULL);

    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    add_vrfy_fingerprint(vbox, vfd);
    g_signal_connect(G_OBJECT(vbox), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);
}

static void redraw_auth_vbox(GtkComboBox *combo, void *data)
{
    AuthSignalData *auth_data = (AuthSignalData*) data;

    GtkWidget *notebook = auth_data ? auth_data->notebook : NULL;

    int selected;

    if (auth_data == NULL) return;

    selected = gtk_combo_box_get_active(combo);

    if (selected == 0) {
	gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 0);
	auth_data->smppair->entry = auth_data->one_way_entry;
	auth_data->smppair->smp_type = 0;
    } else if (selected == 1) {
	gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 1);
	auth_data->smppair->entry = auth_data->two_way_entry;
	auth_data->smppair->smp_type = 1;
    } else if (selected == 2) {
	auth_data->smppair->entry = NULL;
	gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 2);
	auth_data->smppair->smp_type = -1;
    }

}

static void add_other_authentication_options(GtkWidget *vbox,
	GtkWidget *notebook, ConnContext *context, AuthSignalData *data) {
    GtkWidget *label;
    GtkWidget *combo;
    char *labeltext;

    labeltext = g_strdup_printf("\n%s",
	    _("How would you like to authenticate your buddy?"));
    label = gtk_label_new(labeltext);
    g_free(labeltext);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    combo = gtk_combo_box_new_text();

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Question and answer"));

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Shared secret"));

    gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
	    _("Manual fingerprint verification"));

    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    gtk_box_pack_start(GTK_BOX(vbox), combo, FALSE, FALSE, 0);

    data->notebook = notebook;

    g_signal_connect (combo, "changed",
	    G_CALLBACK (redraw_auth_vbox), data);
}


static GtkWidget *create_smp_dialog(const char *title, const char *primary,
	ConnContext *context, gboolean responder, char *question)
{
    GtkWidget *dialog;

    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 1);
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    close_progress_window(smp_data);

    /* If you start SMP authentication on a different context, it
     * will kill any existing SMP */
    if (smp_data->their_instance != context->their_instance) {
	otrg_gtk_dialog_free_smp_data(conv);
	otrg_gtk_dialog_add_smp_data(conv);
    }

    if (!(smp_data->smp_secret_dialog)) {
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *auth_vbox;
	GtkWidget *label;
	GtkWidget *img = NULL;
	char *label_text;
	const char *icon_name = NULL;
	SmpResponsePair* smppair;
	GtkWidget *notebook;
	AuthSignalData *auth_opt_data;

	smp_data->their_instance = context->their_instance;
	icon_name = PIDGIN_STOCK_DIALOG_INFO;
	img = gtk_image_new_from_stock(icon_name,
		gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);

	dialog = gtk_dialog_new_with_buttons(title ? title :
		PIDGIN_ALERT_TITLE, NULL, 0,
		 GTK_STOCK_HELP, GTK_RESPONSE_HELP,
		 GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
		 _("_Authenticate"), GTK_RESPONSE_ACCEPT, NULL);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);

	auth_vbox = gtk_vbox_new(FALSE, 0);
	hbox = gtk_hbox_new(FALSE, 15);
	vbox = gtk_vbox_new(FALSE, 0);

	smppair = malloc(sizeof(SmpResponsePair));
	smppair->responder = responder;
	smppair->context = context;


	notebook = gtk_notebook_new();
	auth_opt_data = malloc(sizeof(AuthSignalData));
	auth_opt_data->smppair = smppair;

	gtk_window_set_focus_on_map(GTK_WINDOW(dialog), !responder);
	gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

	gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
	gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
	gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
	gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
	gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox),
		6);

	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

	gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);

	label_text = g_strdup_printf(
		"<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
		(primary ? primary : ""),
		_("Authenticating a buddy helps ensure that the person "
		"you are talking to is who he or she claims to be."));

	label = gtk_label_new(NULL);

	gtk_label_set_markup(GTK_LABEL(label), label_text);
	gtk_label_set_selectable(GTK_LABEL(label), FALSE);
	g_free(label_text);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	if (!responder) {
	    add_other_authentication_options(vbox, notebook, context,
		    auth_opt_data);
	}

	g_signal_connect(G_OBJECT(dialog), "response",
		G_CALLBACK(smp_secret_response_cb),
		auth_opt_data);

	if (!responder || (responder && question != NULL)) {
	    GtkWidget *one_way_vbox = gtk_vbox_new(FALSE, 0);
	    add_to_vbox_init_one_way_auth(one_way_vbox, context,
		    auth_opt_data, question);
	    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), one_way_vbox,
		    gtk_label_new("0"));
	    smppair->entry = auth_opt_data->one_way_entry;
	    smppair->smp_type = 0;
	}

	if (!responder || (responder && question == NULL)) {
	    GtkWidget *two_way_vbox = gtk_vbox_new(FALSE, 0);
	    add_to_vbox_init_two_way_auth(two_way_vbox, context, auth_opt_data);
	    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), two_way_vbox,
		    gtk_label_new("1"));

	    if (responder && question == NULL) {
		smppair->entry = auth_opt_data->two_way_entry;
		smppair->smp_type = 1;
	    }
	}

	if (!responder) {
	    GtkWidget *fingerprint_vbox = gtk_vbox_new(FALSE, 0);
	    add_to_vbox_verify_fingerprint(fingerprint_vbox, context, smppair);
	    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), fingerprint_vbox,
		    gtk_label_new("2"));
	}

	gtk_notebook_set_show_tabs (GTK_NOTEBOOK(notebook), FALSE);

	gtk_notebook_set_show_border (GTK_NOTEBOOK(notebook), FALSE);
	gtk_box_pack_start(GTK_BOX(auth_vbox), notebook, FALSE, FALSE, 0);
	gtk_widget_show(notebook);


	gtk_box_pack_start(GTK_BOX(vbox), auth_vbox, FALSE, FALSE, 0);

	gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

	gtk_widget_show_all(dialog);

	gtk_notebook_set_current_page (GTK_NOTEBOOK(notebook), 0);

	if (!responder) {
	    gtk_window_set_focus(GTK_WINDOW(dialog),
		    GTK_WIDGET(smppair->question_entry));
	} else {
	    gtk_window_set_focus(GTK_WINDOW(dialog),
		    GTK_WIDGET(smppair->entry));
	}

	smp_data->smp_secret_dialog = dialog;
	smp_data->smp_secret_smppair = smppair;

    } else {
	/* Set the responder field to TRUE if we were passed that value,
	 * even if the window was already up. */
	if (responder) {
	    smp_data->smp_secret_smppair->responder = responder;
	}
    }

    return smp_data->smp_secret_dialog;
}

static GtkWidget *create_smp_progress_dialog(GtkWindow *parent,
	ConnContext *context)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *label;
    GtkWidget *proglabel;
    GtkWidget *bar;
    GtkWidget *img = NULL;
    char *label_text, *label_pat;
    const char *icon_name = NULL;
    PurpleConversation *conv;
    SMPData *smp_data;

    icon_name = PIDGIN_STOCK_DIALOG_INFO;
    img = gtk_image_new_from_stock(icon_name,
	    gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    gtk_misc_set_alignment(GTK_MISC(img), 0, 0);

    dialog = gtk_dialog_new_with_buttons(
	    context->smstate->received_question ?
	    /* Translators: you are asked to authenticate yourself */
	    _("Authenticating to Buddy") :
	    /* Translators: you asked your buddy to authenticate him/herself */
	    _("Authenticating Buddy"),
	    parent, 0, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
	    GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog),
	    GTK_RESPONSE_ACCEPT);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog),
	    GTK_RESPONSE_REJECT, 1);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog),
	    GTK_RESPONSE_ACCEPT, 0);

    gtk_window_set_focus_on_map(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);

    label_pat = g_strdup_printf("<span weight=\"bold\" size=\"larger\">"
	    "%s</span>\n", context->smstate->received_question ?
	    _("Authenticating to %s") :
	    _("Authenticating %s"));
    label_text = g_strdup_printf(label_pat, context->username);
    g_free(label_pat);

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), 1);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    proglabel = gtk_label_new(NULL);
    gtk_label_set_selectable(GTK_LABEL(proglabel), 1);
    gtk_label_set_line_wrap(GTK_LABEL(proglabel), TRUE);
    gtk_misc_set_alignment(GTK_MISC(proglabel), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), proglabel, FALSE, FALSE, 0);

    /* Create the progress bar */
    bar = gtk_progress_bar_new();
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), 0.1);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

    conv = otrg_plugin_context_to_conv(context, 0);
    smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    if (smp_data) {
	smp_data->smp_progress_dialog = dialog;
	smp_data->smp_progress_bar = bar;
	smp_data->smp_progress_label = proglabel;
    }
    gtk_label_set_text(GTK_LABEL(proglabel), _("Waiting for buddy..."));

    g_signal_connect(G_OBJECT(dialog), "response",
	     G_CALLBACK(smp_progress_response_cb),
	     context);

    gtk_widget_show_all(dialog);

    return dialog;
}

/* This is just like purple_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
static void otrg_gtk_dialog_notify_message(PurpleNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    create_dialog(NULL, type, title, primary, secondary, 1, NULL, NULL, NULL);
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
    PurplePlugin *p;
    const char *title = _("Generating private key");
    const char *primary = _("Please wait");
    char *secondary;
    const char *protocol_print;
    GtkWidget *label;
    GtkWidget *dialog;
    OtrgDialogWaitHandle handle;

    p = purple_find_prpl(protocol);
    protocol_print = (p ? p->info->name : _("Unknown"));

    /* Create the Please Wait... dialog */
    secondary = g_strdup_printf(_("Generating private key for %s (%s)..."),
	    account, protocol_print);

    dialog = create_dialog(NULL, PURPLE_NOTIFY_MSG_INFO, title, primary,
	    secondary, 0, &label, NULL, NULL);
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
	const char *protocol, const char *username, const char *msg,
	int force_create)
{
    /* See if there's a conversation window we can put this in. */
    PurpleConversation *conv = otrg_plugin_userinfo_to_conv(accountname,
	    protocol, username, force_create);


    if (!conv) return -1;


    purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    return 0;
}

/* End a Please Wait dialog. */
static void otrg_gtk_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    const char *oldmarkup;
    char *newmarkup;

    oldmarkup = gtk_label_get_label(GTK_LABEL(handle->label));
    newmarkup = g_strdup_printf(_("%s Done."), oldmarkup);

    gtk_label_set_markup(GTK_LABEL(handle->label), newmarkup);
    gtk_widget_show(handle->label);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(handle->dialog),
	    GTK_RESPONSE_ACCEPT, 1);

    g_free(newmarkup);
    free(handle);
}

/* Inform the user that an unknown fingerprint was received. */
static void otrg_gtk_dialog_unknown_fingerprint(OtrlUserState us,
	const char *accountname, const char *protocol, const char *who,
	unsigned char fingerprint[20])
{
    PurpleConversation *conv;
    char *buf;
    ConnContext *context;
    int seenbefore = FALSE;

    /* Figure out if this is the first fingerprint we've seen for this
     * user. */
    context = otrl_context_find(us, who, accountname, protocol,
	    OTRL_INSTAG_MASTER, 0, NULL, NULL, NULL);

    if (context) {
	Fingerprint *fp = context->fingerprint_root.next;
	while(fp) {
	    if (memcmp(fingerprint, fp->fingerprint, 20)) {
		/* This is a previously seen fingerprint for this user,
		 * different from the one we were passed. */
		seenbefore = TRUE;
		break;
	    }
	    fp = fp->next;
	}
    }

    if (seenbefore) {
	buf = g_strdup_printf(_("%s is contacting you from an unrecognized "
		    "computer.  You should <a href=\"%s%s\">authenticate</a> "
		    "this buddy."), who, AUTHENTICATE_HELPURL, _("?lang=en"));
    } else {
	buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
		    "should <a href=\"%s%s\">authenticate</a> this buddy."),
		who, AUTHENTICATE_HELPURL, _("?lang=en"));
    }

    conv = otrg_plugin_userinfo_to_conv(accountname, protocol, who, TRUE);

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);
}

static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void build_otr_menu(ConvOrContext *convctx, GtkWidget *menu,
	TrustLevel level);
static void otr_refresh_otr_buttons(PurpleConversation *conv);
static void otr_destroy_top_menu_objects(PurpleConversation *conv);
static void otr_add_top_otr_menu(PurpleConversation *conv);
static void otr_add_buddy_top_menus(PurpleConversation *conv);
static void otr_check_conv_status_change(PurpleConversation *conv);

static void destroy_menuitem(GtkWidget *widget, gpointer data)
{
    gtk_widget_destroy(widget);
}

static void otr_build_status_submenu(PidginWindow *win,
	ConvOrContext *convctx, GtkWidget *menu, TrustLevel level);

static void dialog_update_label_conv(PurpleConversation *conv, TrustLevel level)
{
    GtkWidget *label;
    GtkWidget *icon;
    GtkWidget *button;
    GtkWidget *menu;
    ConvOrContext *convctx;
    GHashTable * conv_or_ctx_map;
    char *markup;
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    label = purple_conversation_get_data(conv, "otr-label");
    icon = purple_conversation_get_data(conv, "otr-icon");
    button = purple_conversation_get_data(conv, "otr-button");
    menu = purple_conversation_get_data(conv, "otr-menu");

    otr_icon(icon, level, 1);
    markup = g_strdup_printf(" <span color=\"%s\">%s</span>",
	    level == TRUST_FINISHED ? "#000000" :
	    level == TRUST_PRIVATE ? "#00a000" :
	    level == TRUST_UNVERIFIED ? "#a06000" :
	    "#ff0000",
	    level == TRUST_FINISHED ? _("Finished") :
	    level == TRUST_PRIVATE ? _("Private") :
	    level == TRUST_UNVERIFIED ? _("Unverified") :
	    _("Not private"));
    gtk_label_set_markup(GTK_LABEL(label), markup);
    g_free(markup);
    gtk_tooltips_set_tip(gtkconv->tooltips, button, _("OTR"), NULL);


    /* Use any non-NULL value for "private", NULL for "not private" */
    purple_conversation_set_data(conv, "otr-private",
	    (level == TRUST_NOT_PRIVATE || level == TRUST_FINISHED) ?
		    NULL : conv);

    /* Use any non-NULL value for "unauthenticated", NULL for
     * "authenticated" */
    purple_conversation_set_data(conv, "otr-authenticated",
	    (level == TRUST_PRIVATE) ? conv : NULL);

    /* Use any non-NULL value for "finished", NULL for "not finished" */
    purple_conversation_set_data(conv, "otr-finished",
	    level == TRUST_FINISHED ? conv : NULL);

    conv_or_ctx_map = purple_conversation_get_data(conv, "otr-convorctx");
    convctx = g_hash_table_lookup(conv_or_ctx_map, conv);

    if (!convctx) {
	convctx = malloc(sizeof(ConvOrContext));
	g_hash_table_insert(conv_or_ctx_map, conv, (gpointer)convctx);
    }

    convctx->convctx_type = convctx_conv;
    convctx->conv = conv;
    build_otr_menu(convctx, menu, level);
    otr_build_status_submenu(pidgin_conv_get_window(gtkconv), convctx, menu,
	    level);

    conv = gtkconv->active_conv;
    otr_check_conv_status_change(conv);

    /* Update other widgets */
    if (gtkconv != pidgin_conv_window_get_active_gtkconv(gtkconv->win)) {
	return;
    }

    otr_destroy_top_menu_objects(conv);
    otr_add_top_otr_menu(conv);
    otr_refresh_otr_buttons(conv);
    otr_add_buddy_top_menus(conv);
}

static void dialog_update_label(ConnContext *context)
{
    PurpleAccount *account;
    PurpleConversation *conv;
    TrustLevel level = otrg_plugin_context_to_trust(context);


    account = purple_accounts_find(context->accountname, context->protocol);
    if (!account) return;
    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
	    context->username, account);
    if (!conv) return;
    dialog_update_label_conv(conv, level);
}

struct vrfy_fingerprint_data {
    Fingerprint *fprint;   /* You can use this pointer right away, but
			      you can't rely on it sticking around for a
			      while.  Use the copied pieces below
			      instead. */
    char *accountname, *username, *protocol;
    otrl_instag_t their_instance;
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
    vfd->their_instance = context->their_instance;
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
	    vfd->username, vfd->accountname, vfd->protocol, vfd->their_instance,
	    0, NULL, NULL, NULL);
    Fingerprint *fprint;
    int oldtrust, trust;

    if (context == NULL) return;

    fprint = otrl_context_find_fingerprint(context, vfd->fingerprint, 0, NULL);

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
    /* Translators: the following four messages should give alternative
     * sentences. The user selects the first or second message in a combo box;
     * the third message, a new line, a fingerprint, a new line, and
     * the fourth message will follow it. */
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("I have not"));
    /* 2nd message */
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("I have"));
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), verified);
    /* 3rd message */
    label = gtk_label_new(_(" verified that this is in fact the correct"));
    gtk_box_pack_start(GTK_BOX(hbox), combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    g_signal_connect(G_OBJECT(combo), "changed",
	    G_CALLBACK(vrfy_fingerprint_changed), vfd);

    hbox = gtk_hbox_new(FALSE, 0);
    /* 4th message */
    labelt = g_strdup_printf(_("fingerprint for %s."),
	    vfd->username);
    label = gtk_label_new(labelt);
    g_free(labelt);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
}

static void verify_fingerprint(GtkWindow *parent, Fingerprint *fprint)
{
    GtkWidget *dialog;
    char our_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN],
	    their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
    char *primary;
    char *secondary;
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context;
    PurplePlugin *p;
    char *proto_name;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;
    context = fprint->context;
    if (context == NULL) return;

    primary = g_strdup_printf(_("Verify fingerprint for %s"),
	    context->username);
    vfd = vrfy_fingerprint_data_new(fprint);

    strncpy(our_hash, _("[none]"), 44);
    our_hash[44] = '\0';
    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
	    context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");
    secondary = g_strdup_printf(_("<small><i>%s %s\n\n</i></small>"
	    "Fingerprint for you, %s (%s):\n%s\n\n"
	    "Purported fingerprint for %s:\n%s\n"),
	    _("To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other."),
	    _("If everything matches up, you should indicate in the above "
	    "dialog that you <b>have</b> verified the fingerprint."),
	    context->accountname, proto_name, our_hash,
	    context->username, their_hash);

    dialog = create_dialog(parent, PURPLE_NOTIFY_MSG_INFO,
	    _("Verify fingerprint"), primary, secondary, 1, NULL,
	    add_vrfy_fingerprint, vfd);
    g_signal_connect(G_OBJECT(dialog), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);

    g_free(primary);
    g_free(secondary);
}

static void otrg_gtk_dialog_verify_fingerprint(Fingerprint *fprint)
{
    verify_fingerprint(NULL, fprint);
}

/* Create the SMP dialog.  responder is true if this is called in
 * response to someone else's run of SMP. */
static void otrg_gtk_dialog_socialist_millionaires(ConnContext *context,
	char *question, gboolean responder)
{
    char *primary;
    PurplePlugin *p;
    char *proto_name;

    if (context == NULL) return;

    if (responder && question) {
	primary = g_strdup_printf(_("Authentication from %s"),
	    context->username);
    } else {
	primary = g_strdup_printf(_("Authenticate %s"),
	    context->username);
    }

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : _("Unknown");


    create_smp_dialog(_("Authenticate Buddy"),
	    primary, context, responder, question);

    g_free(primary);
}

/* Call this to update the status of an ongoing socialist millionaires
 * protocol.  Progress_level is a percentage, from 0.0 (aborted) to
 * 1.0 (complete).  Any other value represents an intermediate state. */
static void otrg_gtk_dialog_update_smp(ConnContext *context,
	OtrlSMPEvent smp_event, double progress_level)
{
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 0);
    GtkProgressBar *bar;
    SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

    if (!smp_data) return;

    bar = GTK_PROGRESS_BAR(smp_data->smp_progress_bar);
    gtk_progress_bar_set_fraction(bar, progress_level);

    /* If the counter is reset to absolute zero, the protocol has aborted */
    if (progress_level == 0.0) {
	GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);

	gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
		_("An error occurred during authentication."));
	return;
    } else if (progress_level == 1.0) {
	/* If the counter reaches 1.0, the protocol is complete */
	GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
		GTK_RESPONSE_ACCEPT);

	if (smp_event == OTRL_SMPEVENT_SUCCESS) {
	    if (context->active_fingerprint->trust &&
		    context->active_fingerprint->trust[0]) {
		gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
			_("Authentication successful."));
	    } else {
		gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
			_("Your buddy has successfully authenticated you.  "
			"You may want to authenticate your buddy as "
			"well by asking your own question."));
	    }
	} else {
	    gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
		    _("Authentication failed."));
	}
    } else {
	/* Clear the progress label */
	gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label), "");
    }
}

/* Call this when a context transitions to ENCRYPTED. */
static void otrg_gtk_dialog_connected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    char *format_buf;
    TrustLevel level;
    OtrgUiPrefs prefs;
    gboolean * is_multi_inst;

    conv = otrg_plugin_context_to_conv(context, TRUE);
    level = otrg_plugin_context_to_trust(context);

    otrg_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
	    context->username);
    if (prefs.avoid_logging_otr) {
	purple_conversation_set_logging(conv, FALSE);
    }

    switch(level) {
       case TRUST_PRIVATE:
	    format_buf = g_strdup(
		    _("Private conversation with %s started.%s%s"));
	    break;

       case TRUST_UNVERIFIED:
	    format_buf = g_strdup_printf(_("<a href=\"%s%s\">Unverified</a> "
		    "conversation with %%s started.%%s%%s"),
		    UNVERIFIED_HELPURL, _("?lang=en"));
	    break;

       default:
	    /* This last case should never happen, since we know
	     * we're in ENCRYPTED. */
	    format_buf = g_strdup(_("Not private conversation with %s "
		    "started.%s%s"));
	    break;
    }
    buf = g_strdup_printf(format_buf,
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? _("  Warning: using old "
		"protocol version 1.") : "", conv->logging ?
		_("  Your client is logging this conversation.") :
		_("  Your client is not logging this conversation."));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);
    g_free(format_buf);

    dialog_update_label(context);

    is_multi_inst = (gboolean *) purple_conversation_get_data(conv,
	    "otr-conv_multi_instances");

    if (*is_multi_inst) {
	gboolean * have_warned_instances = (gboolean *)
		purple_conversation_get_data(conv, "otr-warned_instances");

	if (!*have_warned_instances) {
	    *have_warned_instances = TRUE;
	    buf = g_strdup_printf(_("Your buddy is logged in multiple times and"
		    " OTR has established <a href=\"%s%s\">multiple sessions"
		    "</a>. Use the icon menu above if you wish to select the "
		    "outgoing session."), SESSIONS_HELPURL, _("?lang=en"));
	    otrg_gtk_dialog_display_otr_message(context->accountname,
		    context->protocol, context->username, buf, 0);
	    g_free(buf);
	}
    }
}

/* Call this when a context transitions to PLAINTEXT. */
static void otrg_gtk_dialog_disconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    OtrgUiPrefs prefs;

    conv = otrg_plugin_context_to_conv(context, 1);

    buf = g_strdup_printf(_("Private conversation with %s lost."),
	    purple_conversation_get_name(conv));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);

    otrg_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
	    context->username);
    if (prefs.avoid_logging_otr) {
	if (purple_prefs_get_bool("/purple/logging/log_ims")) {
	    purple_conversation_set_logging(conv, TRUE);
	}
    }

    dialog_update_label(context);
    close_smp_window(conv);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
static void otrg_gtk_dialog_finished(const char *accountname,
	const char *protocol, const char *username)
{
    /* See if there's a conversation window we can put this in. */
    PurpleAccount *account;
    PurpleConversation *conv;
    ConnContext *context;
    char *buf;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
	    username, account);
    if (!conv) return;

    buf = g_strdup_printf(_("%s has ended his/her private conversation with "
	    "you; you should do the same."),
	    purple_conversation_get_name(conv));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);

    context = otrg_plugin_conv_to_selected_context(conv, 0);
    dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
    close_smp_window(conv);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrg_gtk_dialog_stillconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    char *format_buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    switch(level) {
	case TRUST_PRIVATE:
	    format_buf = g_strdup(_("Successfully refreshed the private "
		    "conversation with %s.%s"));
	    break;

	case TRUST_UNVERIFIED:
	    format_buf = g_strdup_printf(_("Successfully refreshed the "
		    "<a href=\"%s%s\">unverified</a> conversation with "
		    "%%s.%%s"),
		    UNVERIFIED_HELPURL, _("?lang=en"));
	    break;

	default:
	    /* This last case should never happen, since we know
	     * we're in ENCRYPTED. */
	    format_buf = g_strdup(_("Successfully refreshed the not private "
		    "conversation with %s.%s"));
	    break;
    }

    buf = g_strdup_printf(format_buf,
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? _("  Warning: using old "
		"protocol version 1.") : "");

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);
    g_free(format_buf);

    dialog_update_label(context);
}

/* This is called when the OTR button in the button box is clicked, or
 * when the appropriate context menu item is selected. */
static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data)
{
    const char *format;
    char *buf;
    PurpleConversation *conv = data;
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);

    if (gtkconv->active_conv != conv) {
	pidgin_conv_switch_active_conversation(conv);
    }

    if (purple_conversation_get_data(conv, "otr-private")) {
	format = _("Attempting to refresh the private conversation with %s...");
    } else {
	format = _("Attempting to start a private conversation with %s...");
    }
    buf = g_strdup_printf(format, purple_conversation_get_name(conv));

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);

    otrg_plugin_send_default_query_conv(conv);
}

/* Called when SMP verification option selected from menu */
static void socialist_millionaires(GtkWidget *widget, gpointer data)
{
    ConvOrContext *convctx = data;
    PurpleConversation *conv;
    ConnContext *context = NULL;

    if (convctx->convctx_type == convctx_conv) {
	conv = convctx->conv;
	context = otrg_plugin_conv_to_selected_context(conv, 0);
    } else if (convctx->convctx_type == convctx_ctx) {
	context = convctx->context;
    }

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_gtk_dialog_socialist_millionaires(context, NULL, FALSE);
}

static void menu_whatsthis(GtkWidget *widget, gpointer data)
{
    char *uri = g_strdup_printf("%s%s", LEVELS_HELPURL, _("?lang=en"));
    purple_notify_uri(otrg_plugin_handle, uri);
    g_free(uri);
}

static void menu_end_private_conversation(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv;
    ConnContext *context = NULL;
    ConvOrContext *convctx = data;

    if (convctx->convctx_type == convctx_conv) {
	conv = convctx->conv;
	context = otrg_plugin_conv_to_selected_context(conv, 0);
    } else if (convctx->convctx_type == convctx_ctx) {
	context = convctx->context;
    }


    otrg_ui_disconnect_connection(context);
}

static void dialog_resensitize(PurpleConversation *conv);

/* If the OTR button is right-clicked, show the context menu. */
static gboolean button_pressed(GtkWidget *w, GdkEventButton *event,
	gpointer data)
{
    PurpleConversation *conv = data;

    /* Any button will do */
    if (event->type == GDK_BUTTON_PRESS) {
	GtkWidget *menu = purple_conversation_get_data(conv, "otr-menu");
	if (menu) {
	    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
		    3, event->time);
	    return TRUE;
	}
    }

    return FALSE;
}

static void otrg_gtk_dialog_new_purple_conv(PurpleConversation *conv);


static void otr_refresh_otr_buttons(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );
    GList * list_iter = gtkconv->convs;
    PurpleConversation * current_conv;
    GtkWidget *button;

    for (;list_iter;list_iter = list_iter->next) {

	current_conv = list_iter->data;
	button = purple_conversation_get_data(current_conv, "otr-button");

	if (button) {
	    if (current_conv == gtkconv->active_conv) {
		gtk_widget_show (button);
	    } else {
		gtk_widget_hide (button);
	    }
	}
    }
}

/* Menu has been destroyed -- let's remove it from the menu_list
 * so that it won't be destroyed again. */
static void otr_menu_destroy(GtkWidget *widget, gpointer pdata)
{
    PidginWindow *win = (PidginWindow *) pdata ;
    GtkWidget *top_menu = widget;

    GList * menu_list = g_hash_table_lookup ( otr_win_menus, win );
    menu_list = g_list_remove ( menu_list, top_menu );
    g_hash_table_replace ( otr_win_menus, win, menu_list );
}

static void otr_clear_win_menu_list(PidginWindow *win)
{
    GList * head = g_hash_table_lookup ( otr_win_menus, win ); /* menu_list */
    GList * old_head = 0;

    while(head) {
	old_head = head;
	gtk_object_destroy ( GTK_OBJECT ( head->data ) );
	head = g_hash_table_lookup ( otr_win_menus, win );

	if (head && head == old_head) {
	    /* The head was not removed by the "destroyed" callback
	       Something is wrong */
	    break;
	}
    }

    g_hash_table_replace ( otr_win_menus, win, head );
}

static void otr_destroy_top_menu_objects(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );
    PidginWindow *win = pidgin_conv_get_window ( gtkconv );

    otr_clear_win_menu_list(win);
}

static int otr_get_menu_insert_pos(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );
    PidginWindow *win = pidgin_conv_get_window ( gtkconv );
    GtkWidget *menu_bar = win->menu.menubar;

    GList * list_iter = gtk_container_get_children(GTK_CONTAINER(menu_bar));
    GList * head = list_iter;

    int pos = 0;
    while ( list_iter ) {
	pos++;
	list_iter = list_iter->next;
    }

    if (pos != 0) pos--;

    g_list_free ( head );

    return pos;
}

static void otr_set_menu_labels(ConvOrContext *convctx, GtkWidget *query,
	GtkWidget *end, GtkWidget *smp) {
    PurpleConversation *conv;
    int insecure = 0;
    int authen = 0;
    int finished = 0;
    TrustLevel level = TRUST_NOT_PRIVATE;


    if (convctx->convctx_type == convctx_conv) {
	conv = convctx->conv;
	insecure = purple_conversation_get_data(conv, "otr-private") ? 0 : 1;
	authen = purple_conversation_get_data(conv, "otr-authenticated") ? 1 :0;
	finished = purple_conversation_get_data(conv, "otr-finished") ? 1 : 0;
    } else if (convctx->convctx_type == convctx_ctx) {
	level = otrg_plugin_context_to_trust(convctx->context);
	insecure = level == TRUST_UNVERIFIED || level == TRUST_PRIVATE ? 0 : 1;
	authen = level == TRUST_PRIVATE ? 1 : 0;
	finished = level == TRUST_FINISHED ? 1 : 0;
    } else {
	return;
    }

    GtkWidget * label = gtk_bin_get_child(GTK_BIN(query));

    gtk_label_set_markup_with_mnemonic(GTK_LABEL(label),
	    insecure ? _("Start _private conversation") :
	    _("Refresh _private conversation"));

    label = gtk_bin_get_child(GTK_BIN(smp));

    gtk_label_set_markup_with_mnemonic(GTK_LABEL(label),
	    (!insecure && authen) ? _("Re_authenticate buddy") :
	    _("_Authenticate buddy"));

    gtk_widget_set_sensitive(GTK_WIDGET(end), !insecure || finished);
    gtk_widget_set_sensitive(GTK_WIDGET(smp), !insecure);
}

static void force_deselect(GtkItem *item, gpointer data)
{
    gtk_item_deselect(item);
}

static void otr_build_status_submenu(PidginWindow *win,
	ConvOrContext *convctx, GtkWidget *menu, TrustLevel level) {
    char *status = "";
    GtkWidget *image;
    GtkWidget *levelimage;
    GtkWidget *buddy_name;
    GtkWidget *buddy_status;
    GtkWidget *menusep, *menusep2;
    GdkPixbuf *pixbuf;
    GtkWidget *whatsthis;

    gchar *text = NULL;

    PurpleConversation *conv;

    if (convctx->convctx_type == convctx_conv) {
	conv = convctx->conv;
    } else if (convctx->convctx_type == convctx_ctx) {
	conv = otrg_plugin_context_to_conv(convctx->context, 0);
    } else {
	return;
    }

    text = g_strdup_printf("%s (%s)", conv->name,
	    purple_account_get_username(conv->account));

    buddy_name = gtk_image_menu_item_new_with_label(text);
    g_free(text);

    /* Create a pixmap for the protocol icon. */
    pixbuf = pidgin_create_prpl_icon(conv->account, PIDGIN_PRPL_ICON_SMALL);

    /* Now convert it to GtkImage */
    if (pixbuf == NULL) {
	image = gtk_image_new();
    } else {
	image = gtk_image_new_from_pixbuf(pixbuf);
    }

    gtk_image_menu_item_set_image ( GTK_IMAGE_MENU_ITEM ( buddy_name ), image);

    switch(level) {
	case TRUST_NOT_PRIVATE:
	    status = _("Not Private");
	    break;
	case TRUST_UNVERIFIED:
	    status = _("Unverified");
	    break;
	case TRUST_PRIVATE:
	    status = _("Private");
	    break;
	case TRUST_FINISHED:
	    status = _("Finished");
	    break;
	}

    buddy_status = gtk_image_menu_item_new_with_label(status);

    levelimage = otr_icon(NULL, level, 1);

    gtk_image_menu_item_set_image ( GTK_IMAGE_MENU_ITEM ( buddy_status ),
	    levelimage);

    menusep = gtk_separator_menu_item_new();
    menusep2 = gtk_separator_menu_item_new();
    whatsthis = gtk_image_menu_item_new_with_mnemonic(_("_What's this?"));
    gtk_image_menu_item_set_image ( GTK_IMAGE_MENU_ITEM ( whatsthis ),
	    gtk_image_new_from_stock(GTK_STOCK_HELP,
	    gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_EXTRA_SMALL)));

    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_name);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_status);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep2);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), whatsthis);

    gtk_widget_show(menusep);
    gtk_widget_show_all(buddy_name);
    gtk_widget_show_all(buddy_status);
    gtk_widget_show(menusep2);
    gtk_widget_show_all(whatsthis);

    gtk_signal_connect(GTK_OBJECT(buddy_name), "select",
	GTK_SIGNAL_FUNC(force_deselect), NULL);
    gtk_signal_connect(GTK_OBJECT(buddy_status), "select",
	GTK_SIGNAL_FUNC(force_deselect), NULL);
    gtk_signal_connect(GTK_OBJECT(whatsthis), "activate",
	GTK_SIGNAL_FUNC(menu_whatsthis), conv);
}

static void build_otr_menu(ConvOrContext *convctx, GtkWidget *menu,
	TrustLevel level)
{
    PurpleConversation *conv;

    if (convctx->convctx_type == convctx_conv) {
	conv = convctx->conv;
    } else if (convctx->convctx_type == convctx_ctx) {
	conv = otrg_plugin_context_to_conv(convctx->context, 0);
    } else {
	return;
    }

    GtkWidget *buddymenuquery = gtk_menu_item_new_with_mnemonic(
	    _("Start _private conversation"));
    GtkWidget *buddymenuend = gtk_menu_item_new_with_mnemonic(
	    _("_End private conversation"));
    GtkWidget *buddymenusmp = gtk_menu_item_new_with_mnemonic(
	    _("_Authenticate buddy"));

    otr_set_menu_labels(convctx, buddymenuquery, buddymenuend, buddymenusmp);

    /* Empty out the menu */
    gtk_container_foreach(GTK_CONTAINER(menu), destroy_menuitem, NULL);

    gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenuquery);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenuend);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenusmp);

    gtk_widget_show(buddymenuquery);
    gtk_widget_show(buddymenuend);
    gtk_widget_show(buddymenusmp);

    gtk_signal_connect(GTK_OBJECT(buddymenuquery), "activate",
	GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    gtk_signal_connect(GTK_OBJECT(buddymenuend), "activate",
	GTK_SIGNAL_FUNC(menu_end_private_conversation), convctx);
    gtk_signal_connect(GTK_OBJECT(buddymenusmp), "activate",
	GTK_SIGNAL_FUNC(socialist_millionaires), convctx);

}

static void otr_add_top_otr_menu(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );
    PidginWindow *win = pidgin_conv_get_window ( gtkconv );
    GtkWidget *menu_bar = win->menu.menubar;

    GList * menu_list = g_hash_table_lookup ( otr_win_menus, win );

    GtkWidget *topmenu;
    GtkWidget *topmenuitem;

    TrustLevel level = TRUST_NOT_PRIVATE;
    ConnContext *context = otrg_plugin_conv_to_selected_context(conv, 1);

    ConvOrContext *convctx;

    GHashTable * conv_or_ctx_map = purple_conversation_get_data(conv,
	    "otr-convorctx");

    int pos = otr_get_menu_insert_pos(conv);

    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    topmenuitem = gtk_menu_item_new_with_label ( "OTR" );
    topmenu = gtk_menu_new();

    if (context != NULL) {
	level = otrg_plugin_context_to_trust(context);
    }

    convctx = g_hash_table_lookup(conv_or_ctx_map, conv);

    if (!convctx) {
	convctx = malloc(sizeof(ConvOrContext));
	g_hash_table_insert(conv_or_ctx_map, conv, (gpointer)convctx);
    }

    convctx->convctx_type = convctx_conv;
    convctx->conv = conv;
    build_otr_menu(convctx, topmenu, level);
    otr_build_status_submenu(win, convctx, topmenu, level);

    gtk_menu_item_set_submenu ( GTK_MENU_ITEM ( topmenuitem ), topmenu );

    gtk_widget_show(topmenuitem);
    gtk_widget_show(topmenu);

    gtk_menu_shell_insert ( GTK_MENU_SHELL ( menu_bar ), topmenuitem, pos++ );

    g_signal_connect(G_OBJECT(topmenuitem), "destroy",
	    G_CALLBACK(otr_menu_destroy), win);

    menu_list = g_list_append(menu_list, topmenuitem);

    g_hash_table_replace ( otr_win_menus, win, menu_list );
}

static GList* otr_get_full_buddy_list(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );

    GList *pres_list = NULL;
    GList *conv_list = NULL;

    GSList *l, *buds;

    /* This code is derived from pidgin's 'generating sendto menu' stuff */
    if ( gtkconv->active_conv->type == PURPLE_CONV_TYPE_IM ) {
	buds = purple_find_buddies ( gtkconv->active_conv->account,
		gtkconv->active_conv->name );

	if ( buds == NULL
		&& !g_list_find(conv_list, conv)) {  /* buddy not on list */
	    conv_list = g_list_prepend ( conv_list, conv);
	} else  {
	    for ( l = buds; l != NULL; l = l->next ) {
		PurpleBlistNode *node = ( PurpleBlistNode * )
			purple_buddy_get_contact ( ( PurpleBuddy * ) l->data );

		for ( node = node->child; node != NULL; node = node->next ) {
		    PurpleBuddy *buddy = ( PurpleBuddy * ) node;
		    PurpleAccount *account;

		    if ( !PURPLE_BLIST_NODE_IS_BUDDY ( node ) )
			continue;

		    account = purple_buddy_get_account ( buddy );
		    if ( purple_account_is_connected ( account ) ) {
			/* Use the PurplePresence to get unique buddies. */
			PurplePresence *presence =
				purple_buddy_get_presence( buddy );
			if ( !g_list_find ( pres_list, presence ) ) {

			    PurpleConversation * currentConv =
				    purple_find_conversation_with_account(
				    PURPLE_CONV_TYPE_IM, \
				    purple_buddy_get_name ( buddy ),
				    purple_buddy_get_account ( buddy ));

			    pres_list = g_list_prepend ( pres_list, presence );

			    if (currentConv != NULL &&
				    !g_list_find(conv_list, currentConv)) {
				conv_list = g_list_prepend ( conv_list,
					currentConv );
			    }

			}
		    }
		}
	    }

	    g_slist_free ( buds );
	    g_list_free( pres_list );
	}
    }

    return conv_list;
}

static void unselect_meta_ctx(PurpleConversation *conv)
{
    GtkWidget *select_best = (GtkWidget *) purple_conversation_get_data(conv,
	    "otr-select_best");
    GtkWidget *select_recent = (GtkWidget *) purple_conversation_get_data(conv,
	    "otr-select_recent");

    GTK_CHECK_MENU_ITEM(select_recent)->active = 0;
    GTK_CHECK_MENU_ITEM(select_best)->active = 0;
}

static void select_meta_ctx(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv = (PurpleConversation *) data;
    GtkWidget *select_best = (GtkWidget *) purple_conversation_get_data(conv,
	    "otr-select_best");
    GtkWidget *select_recent = (GtkWidget *) purple_conversation_get_data(conv,
	    "otr-select_recent");
    gboolean value = FALSE;
    otrl_instag_t * selected_instance = (otrl_instag_t *)
	    purple_conversation_get_data(conv, "otr-ui_selected_ctx");
    ConnContext * context = NULL;
    ConnContext * recent_context = NULL;

    value = gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(widget));

    if (widget == select_best) {
	GTK_CHECK_MENU_ITEM(select_recent)->active = !value;

	if (value) {
	    if (selected_instance) {
		*selected_instance = OTRL_INSTAG_BEST;
	    }
	    context = (ConnContext *) otrg_plugin_conv_to_selected_context(conv,
		    1);

	    recent_context = (ConnContext *) otrg_plugin_conv_to_context(conv,
		    OTRL_INSTAG_RECENT_RECEIVED, 0);
	    if (context != recent_context) {
		gchar *buf = g_strdup_printf(_("Warning: The selected outgoing "
			"OTR session (%u) is not the most recently active "
			"one (%u). Your buddy may not receive your messages."
			" Use the icon menu above to select a different "
			"outgoing session."),
			get_context_instance_to_index(conv, context),
			get_context_instance_to_index(conv, recent_context));
		otrg_gtk_dialog_display_otr_message(context->accountname,
			context->protocol, context->username, buf, 0);
		g_free(buf);
	    }

	}

    } else if (widget == select_recent) {
	GTK_CHECK_MENU_ITEM(select_best)->active = !value;

	if (value && selected_instance) {
	    *selected_instance = OTRL_INSTAG_RECENT_RECEIVED;
	}
    }

    if (!context) context = (ConnContext *)
	    otrg_plugin_conv_to_selected_context(conv, 1);

    pidgin_conv_switch_active_conversation(conv);
    dialog_update_label(context);
}

static void select_menu_ctx(GtkWidget *widget, gpointer data)
{
    ConnContext *context = (ConnContext *) data;
    PurpleConversation *conv = otrg_plugin_context_to_conv(context, 1);
    ConnContext *recent_context = (ConnContext *) otrg_plugin_conv_to_context(
	    conv, (otrl_instag_t)OTRL_INSTAG_RECENT_RECEIVED, 0);
    otrl_instag_t *selected_instance = (otrl_instag_t *)
	    purple_conversation_get_data(conv, "otr-ui_selected_ctx");
    gboolean *is_multi_instance = purple_conversation_get_data(conv,
		    "otr-conv_multi_instances");

    if (is_multi_instance && *is_multi_instance) {
	if (selected_instance) {
	    *selected_instance = context->their_instance;
	}
	unselect_meta_ctx(conv);
    }

    pidgin_conv_switch_active_conversation(conv);
    dialog_update_label(context);

    if (is_multi_instance && *is_multi_instance && context != recent_context) {
	gchar *buf = g_strdup_printf(_("Warning: The selected outgoing OTR "
		"session (%u) is not the most recently active one (%u). "
		"Your buddy may not receive your messages. Use the icon menu "
		"above to select a different outgoing session."),
		get_context_instance_to_index(conv, context),
		get_context_instance_to_index(conv, recent_context));
	otrg_gtk_dialog_display_otr_message(context->accountname,
		context->protocol, context->username, buf, 0);
	g_free(buf);
    }
}

static void build_meta_instance_submenu( PurpleConversation *conv,
	GtkWidget *menu) {
    GtkWidget *menusep = gtk_separator_menu_item_new();
    GtkWidget *select_best = gtk_check_menu_item_new_with_label(
	    _("Send to most secure"));
    GtkWidget *select_recent = gtk_check_menu_item_new_with_label(
	    _("Send to most recent"));
    otrl_instag_t * selected_instance = purple_conversation_get_data(conv,
	    "otr-ui_selected_ctx");

    if (!selected_instance || *selected_instance == OTRL_INSTAG_BEST) {
	GTK_CHECK_MENU_ITEM(select_recent)->active = 0;
	GTK_CHECK_MENU_ITEM(select_best)->active = 1;
    } else if (*selected_instance == OTRL_INSTAG_RECENT_RECEIVED) {
	GTK_CHECK_MENU_ITEM(select_recent)->active = 1;
	GTK_CHECK_MENU_ITEM(select_best)->active = 0;
    } else {
	GTK_CHECK_MENU_ITEM(select_recent)->active = 0;
	GTK_CHECK_MENU_ITEM(select_best)->active = 0;
    }

    purple_conversation_set_data(conv, "otr-select_best", select_best);
    purple_conversation_set_data(conv, "otr-select_recent", select_recent);

    gtk_signal_connect(GTK_OBJECT(select_best), "toggled",
	    GTK_SIGNAL_FUNC(select_meta_ctx), conv);
    gtk_signal_connect(GTK_OBJECT(select_recent), "toggled",
	    GTK_SIGNAL_FUNC(select_meta_ctx), conv);

    gtk_widget_show(menusep);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_widget_show(select_best);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), select_best);
    gtk_widget_show(select_recent);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), select_recent);
}

/* Build an OTR buddy menu (where the root menu item is an icon corresponding
 * to the conversation status) for a conversation that has multiple instances.
 * The ConnContexts are given in the GList "instances". Keep track of the
 * position this menu was inserted in the "pos" argument. "active_conv"
 * corresponds to whether this conversation is the active PurpleConversation
 * for this PidginConversation pane.
 */
static void otr_add_buddy_instances_top_menu(PidginConversation *gtkconv,
		GList *instances, gboolean active_conv, const char *username,
		const char *accountname, int *pos) {
    PidginWindow *win = pidgin_conv_get_window ( gtkconv );
    GtkWidget *menu_bar = win->menu.menubar;
    GtkWidget *menu;
    GtkWidget *menu_image;
    GtkWidget * tooltip_menu;
    gchar *tooltip_text;
    gpointer gp_instance;
    otrl_instag_t * selected_instance = NULL;
    gboolean selection_exists = 0;
    ConnContext * context = instances->data;
    TrustLevel level = TRUST_NOT_PRIVATE;
    GHashTable * conv_or_ctx_map;
    PurpleConversation * conv = NULL;
    ConvOrContext convctx;
    GList * menu_list;

    conv = otrg_plugin_context_to_conv(context, 0);
    selection_exists = g_hash_table_lookup_extended(conv->data,
	    "otr-ui_selected_ctx", NULL, &gp_instance);

    /* Find the selected or default instance */
    if (selection_exists) {
	selected_instance = gp_instance;
	context = otrl_context_find(otrg_plugin_userstate,
		context->username, context->accountname, context->protocol,
		*selected_instance, 0, NULL, NULL, NULL);
    } else {
	context = otrl_context_find(otrg_plugin_userstate,
		context->username, context->accountname, context->protocol,
		OTRL_INSTAG_BEST, 0, NULL, NULL, NULL);
    }

    menu = gtk_menu_new();

    conv_or_ctx_map = purple_conversation_get_data(conv, "otr-convorctx");

    for (; instances; instances = instances->next) {
	GtkWidget *instance_menu_item;
	GtkWidget *instance_submenu;
	gchar* text;
	ConnContext *curr_context = instances->data;
	ConvOrContext * curr_convctx = g_hash_table_lookup(conv_or_ctx_map,
		curr_context);
	gboolean selected = (curr_context->their_instance ==
		context->their_instance);
	gint instance_i = -1;

	if (curr_context->m_context == curr_context &&
		curr_context->msgstate == OTRL_MSGSTATE_PLAINTEXT) {
	    continue;
	}

	if (!curr_convctx) {
	    curr_convctx = malloc(sizeof(ConvOrContext));
	    g_hash_table_insert(conv_or_ctx_map, curr_context,
		    (gpointer)curr_convctx);
	    curr_convctx->convctx_type = convctx_ctx;
	    curr_convctx->context = curr_context;
	}


	instance_i = get_context_instance_to_index(conv, curr_context);

	text = g_strdup_printf(_("Session %u"), instance_i);

	instance_menu_item = gtk_image_menu_item_new_with_label(text);
	instance_submenu = gtk_menu_new();

	level = otrg_plugin_context_to_trust(curr_context);
	menu_image = otr_icon(NULL, level, selected);

	gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(instance_menu_item),
		menu_image);
	gtk_image_menu_item_set_always_show_image(
		GTK_IMAGE_MENU_ITEM(instance_menu_item), 1);

	build_otr_menu(curr_convctx, instance_submenu, level);

	g_free(text);

	if (!selection_exists ||
		*selected_instance != curr_context->their_instance) {
	    GtkWidget *select_ctx = gtk_menu_item_new_with_label(_("Select"));
	    GtkWidget *menusep = gtk_separator_menu_item_new();

	    gtk_signal_connect(GTK_OBJECT(select_ctx), "activate",
		    GTK_SIGNAL_FUNC(select_menu_ctx), curr_context);

	    gtk_menu_shell_prepend(GTK_MENU_SHELL(instance_submenu), menusep);
	    gtk_widget_show(menusep);

	    gtk_menu_shell_prepend(GTK_MENU_SHELL(instance_submenu),
		    select_ctx);
	    gtk_widget_show(select_ctx);
	} else if (selection_exists && 
		*selected_instance == curr_context->their_instance) {
	    GtkWidget *selected_ctx =
		    gtk_menu_item_new_with_label(_("Selected"));
	    GtkWidget *menusep = gtk_separator_menu_item_new();

	    gtk_signal_connect(GTK_OBJECT(selected_ctx), "select",
		    GTK_SIGNAL_FUNC(force_deselect), NULL);

	    gtk_menu_shell_prepend(GTK_MENU_SHELL(instance_submenu), menusep);
	    gtk_widget_show(menusep);

	    gtk_menu_shell_prepend(GTK_MENU_SHELL(instance_submenu),
		    selected_ctx);
	    gtk_widget_show(selected_ctx);
	}

	gtk_widget_show(menu_image);
	gtk_widget_show(instance_menu_item);
	gtk_widget_show(instance_submenu);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (instance_menu_item),
		instance_submenu);

	gtk_menu_shell_append(GTK_MENU_SHELL(menu), instance_menu_item);

    }


    level = otrg_plugin_context_to_trust(context);
    menu_image = otr_icon(NULL, level, active_conv);
    convctx.convctx_type = convctx_ctx;
    convctx.context = context;

    build_meta_instance_submenu(conv, menu);

    otr_build_status_submenu(win, &convctx, menu, level);

    tooltip_menu = tooltip_menu_new();

    gtk_widget_show ( menu_image );
    gtk_widget_show(tooltip_menu);
    gtk_menu_shell_insert ( GTK_MENU_SHELL(menu_bar), tooltip_menu, (*pos)++);
    gtk_menu_item_set_submenu ( GTK_MENU_ITEM(tooltip_menu), menu);

    tooltip_text = g_strdup_printf("%s (%s)", username, accountname);
    tooltip_menu_prepend(TOOLTIP_MENU(tooltip_menu), menu_image, tooltip_text);
    g_free(tooltip_text);

    menu_list = g_hash_table_lookup ( otr_win_menus, win );

    g_signal_connect(G_OBJECT(tooltip_menu), "destroy",
	    G_CALLBACK(otr_menu_destroy), win);

    menu_list = g_list_append(menu_list, tooltip_menu);

    g_hash_table_replace ( otr_win_menus, win, menu_list );
}

/* Build an OTR buddy menu (where the root menu item is an icon corresponding
 * to the conversation status) for a conversation that does not have multiple
 * instances. A pre-allocated ConvOrContext is given. Keep track of the
 * position this menu was inserted in the "pos" argument. "active_conv"
 * corresponds to whether this conversation is the active PurpleConversation
 * for this PidginConversation pane.
 */
static void otr_add_buddy_top_menu(PidginConversation *gtkconv,
	ConvOrContext *convctx, gboolean active_conv, const char *username,
	const char *accountname, int *pos) {
    PidginWindow *win = pidgin_conv_get_window ( gtkconv );
    GtkWidget *menu_bar = win->menu.menubar;
    GtkWidget *menu;
    GtkWidget *menu_image;
    TrustLevel level;
    ConnContext *context = NULL;
    GList * menu_list;
    GtkWidget * tooltip_menu;
    gchar *tooltip_text;
    GtkWidget *select_ctx = NULL;

    if (convctx->convctx_type == convctx_ctx) {
	context = convctx->context;
    } else if (convctx->convctx_type == convctx_conv) {
	context = otrg_plugin_conv_to_selected_context(convctx->conv, 0);
    }

    level = TRUST_NOT_PRIVATE;

    if (context != NULL) {
	level = otrg_plugin_context_to_trust(context);
    }

    menu_image = otr_icon(NULL, level, active_conv);

    menu = gtk_menu_new();

    build_otr_menu(convctx, menu, level);
    otr_build_status_submenu(win, convctx, menu, level);

    if (!active_conv) {
	select_ctx = gtk_menu_item_new_with_label(_("Select"));

	gtk_menu_shell_prepend(GTK_MENU_SHELL(menu), select_ctx);
	gtk_widget_show(select_ctx);

	gtk_signal_connect(GTK_OBJECT(select_ctx), "activate",
	GTK_SIGNAL_FUNC(select_menu_ctx), context);
    }

    tooltip_menu = tooltip_menu_new();

    gtk_widget_show ( menu_image );
    gtk_widget_show(tooltip_menu);
    gtk_menu_shell_insert ( GTK_MENU_SHELL(menu_bar), tooltip_menu, (*pos)++);
    gtk_menu_item_set_submenu ( GTK_MENU_ITEM ( tooltip_menu ), menu );

    tooltip_text = g_strdup_printf("%s (%s)", username, accountname);
    tooltip_menu_prepend(TOOLTIP_MENU(tooltip_menu), menu_image, tooltip_text);
    g_free(tooltip_text);

    menu_list = g_hash_table_lookup ( otr_win_menus, win );

    g_signal_connect(G_OBJECT(tooltip_menu), "destroy",
	    G_CALLBACK(otr_menu_destroy), win);

    menu_list = g_list_append(menu_list, tooltip_menu);

    g_hash_table_replace ( otr_win_menus, win, menu_list );
}

static void otr_add_buddy_top_menus(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION ( conv );

    PurpleConversation * currentConv = NULL; /* Auxiliary variables re-used */
    ConnContext *currentContext = NULL;      /* within loops. */

    GList *full_buddy_list = NULL;
    GList *list_iter;

    int pos = otr_get_menu_insert_pos(conv);


    GHashTable *conv_to_context_map = g_hash_table_new(g_direct_hash,
	    g_direct_equal);

    GHashTable * conv_or_ctx_map = purple_conversation_get_data(conv,
	    "otr-convorctx");

    full_buddy_list = otr_get_full_buddy_list(conv);

    list_iter = full_buddy_list;

    /* First determine how many contexts are associated with each conv */
    for (list_iter = g_list_last ( full_buddy_list ); list_iter != NULL;
	    list_iter = list_iter->prev) {
	PurpleAccount *account;
	char *username;
	const char *accountname, *proto;
	GList * contexts = NULL;

	currentConv = list_iter->data;

	if (currentConv == NULL) {
	    continue;
	}

	if (purple_conversation_get_type(currentConv) != PURPLE_CONV_TYPE_IM) {
	    continue;
	}

	account = purple_conversation_get_account(currentConv);
	accountname = purple_account_get_username(account);
	proto = purple_account_get_protocol_id(account);
	username = g_strdup(purple_normalize(account,
		purple_conversation_get_name(currentConv)));

	for (currentContext = otrg_plugin_userstate->context_root;
		currentContext != NULL;
		currentContext = currentContext->next) {

	    if (!strcmp(currentContext->accountname, accountname) &&
		    !strcmp(currentContext->protocol, proto) &&
		    !strcmp(currentContext->username, username)) {
		contexts = g_list_append(contexts, currentContext);
	    }
	}

	g_free(username);

	g_hash_table_insert(conv_to_context_map,
		currentConv, (gpointer) contexts);

    }

    list_iter = full_buddy_list;

    for (list_iter = g_list_last ( full_buddy_list ); list_iter != NULL;
	    list_iter = list_iter->prev) {
	GList * contexts = NULL;
	GList * contexts_iter = NULL;
	gboolean active_conv = 0;
	ConvOrContext * convctx = NULL;
	ConnContext * m_context = NULL;
	PurpleAccount * account = NULL;
	char * username = NULL;
	const char * accountname = NULL;
	int num_contexts = 0;
	gboolean * is_multi_instance;

	currentConv = list_iter->data;

	if (currentConv == NULL) {
	    continue;
	}

	active_conv = (currentConv == gtkconv->active_conv);

	contexts = (GList *) g_hash_table_lookup(conv_to_context_map,
		currentConv);

	if (purple_conversation_get_type(currentConv) != PURPLE_CONV_TYPE_IM) {
	    continue;
	}

	num_contexts = g_list_length(contexts);

	is_multi_instance = purple_conversation_get_data(currentConv,
		    "otr-conv_multi_instances");
	if (is_multi_instance) {
	    *is_multi_instance = FALSE;
	}

	if (num_contexts > 1) {
	    /* We will need the master context */
	    currentContext = (ConnContext *) contexts->data;

	    m_context = currentContext->m_context;
	}

	if (num_contexts <= 1) {
	    /* Just add a menu for the possibly not yet created master inst */
	    convctx = g_hash_table_lookup(conv_or_ctx_map, currentConv);

	    if (!convctx) {
		convctx = malloc(sizeof(ConvOrContext));
		g_hash_table_insert(conv_or_ctx_map, currentConv,
			(gpointer)convctx);
		convctx->convctx_type = convctx_conv;
		convctx->conv = currentConv;
	    }

	    account = purple_conversation_get_account(currentConv);
	    accountname = purple_account_get_username(account);
	    username = g_strdup(
		    purple_normalize(account,
			    purple_conversation_get_name(currentConv)));

	    otr_add_buddy_top_menu(gtkconv, convctx, active_conv, username,
		    accountname, &pos);
	    g_free(username);

	} else if (num_contexts == 2 &&
		m_context->msgstate == OTRL_MSGSTATE_PLAINTEXT) {
	    /* Just add a menu for the non_master instance */
	    contexts_iter = contexts;
	    currentContext = contexts_iter->data;

	    while (currentContext->m_context == currentContext &&
		    contexts_iter->next != NULL) {
		contexts_iter = contexts_iter->next;
		currentContext = contexts_iter->data;
	    }

	    convctx = g_hash_table_lookup(conv_or_ctx_map, currentContext);

	    if (!convctx) {
		convctx = malloc(sizeof(ConvOrContext));
		g_hash_table_insert(conv_or_ctx_map, currentContext,
			(gpointer)convctx);
		convctx->convctx_type = convctx_ctx;
		convctx->context = currentContext;
	    }

	    otr_add_buddy_top_menu(gtkconv, convctx, active_conv,
		    currentContext->username, currentContext->accountname,
		    &pos);

	} else {
	    /* Multi-instances */
	    *is_multi_instance = TRUE;
	    otr_add_buddy_instances_top_menu(gtkconv, contexts, active_conv,
		    currentContext->username, currentContext->accountname,
		    &pos);
	}

	if (contexts) {
	    g_list_free(contexts);
	}
    }

    g_hash_table_destroy (conv_to_context_map);
    g_list_free ( full_buddy_list );

}


static void otr_check_conv_status_change( PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    TrustLevel current_level = TRUST_NOT_PRIVATE;
    ConnContext *context = otrg_plugin_conv_to_context(conv,
	    OTRL_INSTAG_RECENT, 0);

    TrustLevel *previous_level;
    char *buf;
    char *status = "";

    if (context != NULL) {
	current_level = otrg_plugin_context_to_trust(context);
    }

    previous_level = g_hash_table_lookup ( otr_win_status, gtkconv );

    if (!previous_level ||
	    (previous_level && *previous_level == current_level)) {
	return;
    }

    buf = _("The privacy status of the current conversation is now: "
	    "<a href=\"%s%s\">%s</a>");

    switch(current_level) {
	case TRUST_NOT_PRIVATE:
	    status = _("Not Private");
	    break;
	case TRUST_UNVERIFIED:
	    status = _("Unverified");
	    break;
	case TRUST_PRIVATE:
	    status = _("Private");
	    break;
	case TRUST_FINISHED:
	    status = _("Finished");
	    break;
    }

    buf = g_strdup_printf(buf, LEVELS_HELPURL, _("?lang=en"), status);

    /* Write a new message indicating the level change. The timestamp image will
     * be appended as the message timestamp signal is caught, which will also
     * update the privacy level for this gtkconv */
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
	    time(NULL));

    g_free(buf);

}

/* If the conversation switches on us */
static void conversation_switched ( PurpleConversation *conv, void * data )
{
    if ( conv == NULL ) return;

    otrg_gtk_dialog_new_purple_conv(conv);

}

/* If the conversation gets destroyed on us, clean up the data we stored
 * pointing to it. */
static void conversation_destroyed(PurpleConversation *conv, void *data)
{
    GtkWidget *menu = (GtkWidget *) purple_conversation_get_data(conv,
	    "otr-menu");
    PidginConversation *gtkconv;
    PidginWindow *win;
    GHashTable * conv_or_ctx_map;
    GHashTable * conv_to_idx_map;
    gint * max_instance_idx;
    gboolean * is_conv_multi_instance;
    gboolean * have_warned_instances;
    otrl_instag_t * last_received_instance;

    if (menu) gtk_object_destroy(GTK_OBJECT(menu));

    conv_or_ctx_map = purple_conversation_get_data(conv, "otr-convorctx");
    g_hash_table_destroy(conv_or_ctx_map);

    conv_to_idx_map = purple_conversation_get_data(conv, "otr-conv_to_idx");
    g_hash_table_destroy(conv_to_idx_map);

    max_instance_idx = purple_conversation_get_data(conv, "otr-max_idx");
    if (max_instance_idx) {
	g_free(max_instance_idx);
    }

    is_conv_multi_instance = purple_conversation_get_data(conv,
	    "otr-conv_multi_instances");
    if (is_conv_multi_instance) {
	g_free(is_conv_multi_instance);
    }

    have_warned_instances = purple_conversation_get_data(conv,
	    "otr-warned_instances");
    if (have_warned_instances) {
	g_free(have_warned_instances);
    }

    last_received_instance = purple_conversation_get_data(conv,
	    "otr-last_received_ctx");
    if (last_received_instance) {
	g_free(last_received_instance);
    }

    g_hash_table_remove(conv->data, "otr-label");
    g_hash_table_remove(conv->data, "otr-button");
    g_hash_table_remove(conv->data, "otr-icon");
    g_hash_table_remove(conv->data, "otr-menu");
    g_hash_table_remove(conv->data, "otr-private");
    g_hash_table_remove(conv->data, "otr-authenticated");
    g_hash_table_remove(conv->data, "otr-finished");
    g_hash_table_remove(conv->data, "otr-select_best");
    g_hash_table_remove(conv->data, "otr-select_recent");
    g_hash_table_remove(conv->data, "otr-convorctx");
    g_hash_table_remove(conv->data, "otr-conv_to_idx");
    g_hash_table_remove(conv->data, "otr-max_idx");
    g_hash_table_remove(conv->data, "otr-conv_multi_instances");
    g_hash_table_remove(conv->data, "otr-warned_instances");
    g_hash_table_remove(conv->data, "otr-last_received_ctx");

    otrg_gtk_dialog_free_smp_data(conv);

    gtkconv = PIDGIN_CONVERSATION ( conv );

    /* Only delete the OTR menus if we're the active conversation */
    if (gtkconv != pidgin_conv_window_get_active_gtkconv(gtkconv->win)) {
	return;
    }

    win = pidgin_conv_get_window ( gtkconv );

    otr_clear_win_menu_list(win);

    g_hash_table_remove(otr_win_menus, win);

}

/* Set up the per-conversation information display */
static void otrg_gtk_dialog_new_purple_conv(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    ConnContext *context;
    ConvOrContext *convctx;
    GtkWidget *bbox;
    GtkWidget *button;
    GtkWidget *label;
    GtkWidget *bwbox;
    GtkWidget *icon;
    GtkWidget *menu;

    PurpleAccount *account;
    const char *name;
    OtrgUiPrefs prefs;

    GHashTable * conv_or_ctx_map;
    GHashTable * ctx_to_idx_map;

    gint * max_instance_idx;
    gboolean * is_conv_multi_instance;
    gboolean * have_warned_instances;
    otrl_instag_t * last_received_instance;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    /* Get the prefs */
    account = purple_conversation_get_account(conv);
    name = purple_conversation_get_name(conv);
    otrg_ui_get_prefs(&prefs, account, name);

    /* OTR is disabled for this buddy */
    if (prefs.policy == OTRL_POLICY_NEVER) {
	otr_destroy_top_menu_objects(conv);
	return;
    }

    bbox = gtkconv->toolbar;

    context = otrg_plugin_conv_to_selected_context(conv, 0);

    /* See if we're already set up */
    button = purple_conversation_get_data(conv, "otr-button");
    if (button) {
	if (prefs.show_otr_button) {
	    /* Check if we've been removed from the bbox; purple does this
	     * when the user changes her prefs for the style of buttons to
	     * display. */
	    GList *children = gtk_container_get_children(GTK_CONTAINER(bbox));
	    if (!g_list_find(children, button)) {
		gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
	    }
	    g_list_free(children);
	    gtk_widget_show_all(button);
	} else {
	    gtk_container_remove(GTK_CONTAINER(bbox), button);
	    gtk_widget_hide_all(button);
	}
	dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
	return;
    }

    conv_or_ctx_map = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
	    free);
    purple_conversation_set_data(conv, "otr-convorctx", conv_or_ctx_map);

    ctx_to_idx_map = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
	    g_free);
    purple_conversation_set_data(conv, "otr-conv_to_idx", ctx_to_idx_map);

    max_instance_idx = g_malloc(sizeof(gint));
    *max_instance_idx = 0;
    purple_conversation_set_data(conv, "otr-max_idx",
	    (gpointer)max_instance_idx);

    is_conv_multi_instance = g_malloc(sizeof(gboolean));
    *is_conv_multi_instance = FALSE;
    purple_conversation_set_data(conv, "otr-conv_multi_instances",
	    (gpointer)is_conv_multi_instance);

    have_warned_instances = g_malloc(sizeof(gboolean));
    *have_warned_instances = FALSE;
    purple_conversation_set_data(conv, "otr-warned_instances",
	    (gpointer)have_warned_instances);

    last_received_instance = g_malloc(sizeof(otrl_instag_t));
    *last_received_instance = OTRL_INSTAG_BEST; /* cannot be received */
    purple_conversation_set_data(conv, "otr-last_received_ctx",
	    (gpointer)last_received_instance);

    /* Make the button */
    button = gtk_button_new();

    gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    if (prefs.show_otr_button) {
	gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
    }

    bwbox = gtk_hbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(button), bwbox);
    icon = otr_icon(NULL, TRUST_NOT_PRIVATE, 1);
    gtk_box_pack_start(GTK_BOX(bwbox), icon, TRUE, FALSE, 0);
    label = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(bwbox), label, FALSE, FALSE, 0);

    if (prefs.show_otr_button) {
	gtk_widget_show_all(button);
    }

    /* Make the context menu */

    menu = gtk_menu_new();
    gtk_menu_set_title(GTK_MENU(menu), _("OTR Messaging"));

    convctx = malloc(sizeof(ConvOrContext));
    convctx->convctx_type = convctx_conv;
    convctx->conv = conv;
    g_hash_table_replace ( conv_or_ctx_map, conv, convctx );
    build_otr_menu(convctx, menu, TRUST_NOT_PRIVATE);
    otr_build_status_submenu(pidgin_conv_get_window(gtkconv), convctx, menu,
	    TRUST_NOT_PRIVATE);

    purple_conversation_set_data(conv, "otr-label", label);
    purple_conversation_set_data(conv, "otr-button", button);
    purple_conversation_set_data(conv, "otr-icon", icon);
    purple_conversation_set_data(conv, "otr-menu", menu);
    g_signal_connect(G_OBJECT(button), "button-press-event",
	    G_CALLBACK(button_pressed), conv);

    dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
    dialog_resensitize(conv);

    /* Finally, add the state for the socialist millionaires dialogs */
    otrg_gtk_dialog_add_smp_data(conv);
}

/* Set up the per-conversation information display */
static void otrg_gtk_dialog_new_conv(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    conversation_switched (gtkconv->active_conv, NULL);
}

/* Remove the per-conversation information display */
static void otrg_gtk_dialog_remove_conv(PurpleConversation *conv)
{
    GtkWidget *button;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    button = purple_conversation_get_data(conv, "otr-button");
    if (button) gtk_object_destroy(GTK_OBJECT(button));

    conversation_destroyed(conv, NULL);
}

/* Set the OTR button to "sensitive" or "insensitive" as appropriate. */
static void dialog_resensitize(PurpleConversation *conv)
{
    PurpleAccount *account;
    PurpleConnection *connection;
    GtkWidget *button;
    const char *name;
    OtrgUiPrefs prefs;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    account = purple_conversation_get_account(conv);
    name = purple_conversation_get_name(conv);
    otrg_ui_get_prefs(&prefs, account, name);

    if (prefs.policy == OTRL_POLICY_NEVER) {
	otrg_gtk_dialog_remove_conv(conv);
    } else {
	otrg_gtk_dialog_new_conv(conv);
    }
    button = purple_conversation_get_data(conv, "otr-button");
    if (!button) return;
    if (account) {
	connection = purple_account_get_connection(account);
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
    purple_conversation_foreach(dialog_resensitize);
}

static void foreach_free_lists(void * key, void * value, void* data)
{
    PidginWindow *win = (PidginWindow *) key;

    otr_clear_win_menu_list(win);
}



static char* conversation_timestamp(PurpleConversation *conv, time_t mtime,
	gboolean show_date) {

    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    TrustLevel current_level = TRUST_NOT_PRIVATE;
    ConnContext *context = (ConnContext *) otrg_plugin_conv_to_context(conv,
	    OTRL_INSTAG_RECENT, 0);
    TrustLevel *previous_level;
    int id;


    if (context != NULL) {
	current_level = otrg_plugin_context_to_trust(context);
    }

    previous_level = g_hash_table_lookup ( otr_win_status, gtkconv );


    if (previous_level && *previous_level == current_level) {
	return NULL;
    }

    /* We want to update this gtkconv's privacy level only if the new privacy
     * level we received corresponds to the active conversation.  */
    if (conv == gtkconv->active_conv) {
	/* 'free' is handled by the hashtable */
	TrustLevel * current_level_ptr = malloc(sizeof(TrustLevel));
	*current_level_ptr = current_level;
	g_hash_table_replace ( otr_win_status, gtkconv, current_level_ptr );
    }

    if (!previous_level) {
	return NULL;
    }

    id = -1;

    switch(current_level) {
	case TRUST_NOT_PRIVATE:
	    id = img_id_not_private;
	    break;
	case TRUST_UNVERIFIED:
	    id = img_id_unverified;
	    break;
	case TRUST_PRIVATE:
	    id = img_id_private;
	    break;
	case TRUST_FINISHED:
	    id = img_id_finished;
	    break;
    }


    if (id > 0 ) {
	char * msg = g_strdup_printf("<IMG ID=\"%d\"> ", id);
	gtk_imhtml_append_text_with_images((GtkIMHtml*)gtkconv->imhtml, msg, 0,
		NULL);
	g_free(msg);
    }


    return NULL;
}

/* If the user has selected a meta instance, an incoming message may trigger an
 * instance change... we need to update the GUI appropriately */
static gboolean check_incoming_instance_change(PurpleAccount *account,
	char *sender, char *message, PurpleConversation *conv,
	PurpleMessageFlags flags) {
    otrl_instag_t * last_received_instance;
    otrl_instag_t selected_instance;
    gboolean have_received = FALSE;
    ConnContext *received_context = NULL;
    ConnContext *current_out = NULL;

    if (!conv || !conv->data) {
	return 0;
    }

    selected_instance = otrg_plugin_conv_to_selected_instag(conv, 0);
    current_out = otrg_plugin_conv_to_selected_context(conv, 0);

    last_received_instance = g_hash_table_lookup(conv->data,
	    "otr-last_received_ctx");

    if (!last_received_instance) {
	return 0; /* OTR disabled for this buddy */
    }

    if (*last_received_instance == OTRL_INSTAG_MASTER || 
	    *last_received_instance >= OTRL_MIN_VALID_INSTAG) {
	have_received = TRUE;
    }

    received_context = (ConnContext *) otrg_plugin_conv_to_context(conv,
	    (otrl_instag_t)OTRL_INSTAG_RECENT_RECEIVED, 0);

    if (!received_context) {
	return 0;
    }

    if (have_received &&
	    *last_received_instance != received_context->their_instance &&
	    selected_instance != OTRL_INSTAG_MASTER &&
	    selected_instance < OTRL_MIN_VALID_INSTAG) {
	dialog_update_label_conv(conv,
		otrg_plugin_context_to_trust(current_out));
    }

    *last_received_instance = received_context->their_instance;

    return 0;
}

static void unref_img_by_id(int *id)
{
    if (id && *id > 0) {
	purple_imgstore_unref_by_id(*id);
	*id = -1;
    }
}

static void dialog_quitting(void)
{
    /* We need to do this by catching the quitting signal, because
     * purple (mistakenly?) frees up all data structures, including
     * the imgstore, *before* calling the unload() method of the
     * plugins. */
    unref_img_by_id(&img_id_not_private);
    unref_img_by_id(&img_id_unverified);
    unref_img_by_id(&img_id_private);
    unref_img_by_id(&img_id_finished);
}

/* Initialize the OTR dialog subsystem */
static void otrg_gtk_dialog_init(void)
{
    otr_win_menus = g_hash_table_new(g_direct_hash, g_direct_equal);
    otr_win_status = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
	    free);


    img_id_not_private = purple_imgstore_add_with_id(
	    g_memdup(not_private_png, sizeof(not_private_png)),
	    sizeof(not_private_png), "");

    img_id_unverified = purple_imgstore_add_with_id(
	    g_memdup(unverified_png, sizeof(unverified_png)),
	    sizeof(unverified_png), "");

    img_id_private = purple_imgstore_add_with_id(
	    g_memdup(private_png, sizeof(private_png)),
	    sizeof(private_png), "");

    img_id_finished = purple_imgstore_add_with_id(
	    g_memdup(finished_png, sizeof(finished_png)),
	    sizeof(finished_png), "");


    purple_signal_connect(pidgin_conversations_get_handle(),
	    "conversation-switched", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_switched), NULL);

    purple_signal_connect(purple_conversations_get_handle(),
	    "deleting-conversation", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_destroyed), NULL);

    purple_signal_connect(pidgin_conversations_get_handle(),
	    "conversation-timestamp", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_timestamp), NULL);

    purple_signal_connect(purple_conversations_get_handle(),
	    "received-im-msg", otrg_plugin_handle,
	    PURPLE_CALLBACK(check_incoming_instance_change), NULL);

    purple_signal_connect(purple_get_core(),
	    "quitting", otrg_plugin_handle,
	    PURPLE_CALLBACK(dialog_quitting), NULL);
}

/* Deinitialize the OTR dialog subsystem */
static void otrg_gtk_dialog_cleanup(void)
{
    purple_signal_disconnect(purple_get_core(), "quitting",
	    otrg_plugin_handle, PURPLE_CALLBACK(dialog_quitting));

    purple_signal_disconnect(pidgin_conversations_get_handle(),
	    "conversation-switched", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_switched));

    purple_signal_disconnect(pidgin_conversations_get_handle(),
	    "conversation-timestamp", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_timestamp));

    purple_signal_disconnect(purple_conversations_get_handle(),
	    "deleting-conversation", otrg_plugin_handle,
	    PURPLE_CALLBACK(conversation_destroyed));

    purple_signal_disconnect(purple_conversations_get_handle(),
	    "received-im-msg", otrg_plugin_handle,
	    PURPLE_CALLBACK(check_incoming_instance_change));

    /* If we're quitting, the imgstore will already have been destroyed
     * by purple, but we should have already called dialog_quitting(),
     * so the img_id_* should be -1, and all should be OK. */
    unref_img_by_id(&img_id_not_private);
    unref_img_by_id(&img_id_unverified);
    unref_img_by_id(&img_id_private);
    unref_img_by_id(&img_id_finished);

    g_hash_table_foreach(otr_win_menus, foreach_free_lists, NULL);

    g_hash_table_destroy(otr_win_menus);

    g_hash_table_destroy(otr_win_status);
}

static const OtrgDialogUiOps gtk_dialog_ui_ops = {
    otrg_gtk_dialog_init,
    otrg_gtk_dialog_cleanup,
    otrg_gtk_dialog_notify_message,
    otrg_gtk_dialog_display_otr_message,
    otrg_gtk_dialog_private_key_wait_start,
    otrg_gtk_dialog_private_key_wait_done,
    otrg_gtk_dialog_unknown_fingerprint,
    otrg_gtk_dialog_verify_fingerprint,
    otrg_gtk_dialog_socialist_millionaires,
    otrg_gtk_dialog_update_smp,
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
