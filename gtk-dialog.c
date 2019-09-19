/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2018  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *                           The pidgin-otrng contributors
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
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>

/* gcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include <core.h>
#include <gtkconv.h>
#include <gtkimhtml.h>
#include <gtkmenutray.h>
#include <gtkutils.h>
#include <notify.h>
#include <pidginstock.h>
#include <plugin.h>
#include <tooltipmenu.h>
#include <util.h>
#include <version.h>

#ifdef ENABLE_NLS
/* internationalisation headers */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

#include <libotr/proto.h>
/* libotr headers */
#include <libotr/dh.h>
#include <libotr/instag.h>
#include <libotr/message.h>
#include <libotr/privkey.h>
#include <libotr/userstate.h>

/* pidgin-otrng headers */
#include "gtk-dialog.h"
#include "otr-icons.h"
#include "pidgin-helpers.h"
#include "plugin-all.h"
#include "ui.h"

static GHashTable *otr_win_menus = 0;
static GHashTable *otr_win_status = 0;

static int img_id_not_private = 0;
static int img_id_unverified = 0;
static int img_id_private = 0;
static int img_id_finished = 0;

#define AUTH_SMP_QUESTION 0
#define AUTH_SMP_SHARED_SECRET 1
#define AUTH_FINGERPRINT_VERIFICATION -1

typedef struct vrfy_fingerprint_data {
  otrng_plugin_fingerprint_s *fprint;
  char *accountname, *protocol;
  otrl_instag_t their_instance;
  int newtrust;
} vrfy_fingerprint_data;

typedef struct {
  otrng_plugin_conversation *conv;

  GtkEntry *question_entry; /* The text entry field containing the user
                             * question */
  GtkEntry *entry;          /* The text entry field containing the secret */
  int smp_type;             /* Whether the SMP type is based on question
                             * challenge (0) or shared secret (1) */
  gboolean responder;       /* Whether or not this is the first side to give
                             * their secret */
  vrfy_fingerprint_data *vfd;
} SmpResponsePair;

/* Information used by the plugin that is specific to both the
 * application and connection. */
typedef struct dialog_context_data {
  GtkWidget *smp_secret_dialog;
  SmpResponsePair *smp_secret_smppair;
  GtkWidget *smp_progress_dialog;
  GtkWidget *smp_progress_bar;
  GtkWidget *smp_progress_label;
  GtkWidget *smp_progress_image;
  otrl_instag_t their_instance;
} SMPData;

typedef struct {
  SmpResponsePair *smppair;
  GtkEntry *one_way_entry;
  GtkEntry *two_way_entry;
  GtkWidget *notebook;
} AuthSignalData;

typedef struct {
  enum { convctx_none, convctx_conv, convctx_ctx } convctx_type;
  PurpleConversation *conv;
  ConnContext *context;
} ConvOrContext;

static void close_progress_window(SMPData *smp_data) {
  if (smp_data->smp_progress_dialog) {
    gtk_dialog_response(GTK_DIALOG(smp_data->smp_progress_dialog),
                        GTK_RESPONSE_REJECT);
  }
  smp_data->smp_progress_dialog = NULL;
  smp_data->smp_progress_bar = NULL;
  smp_data->smp_progress_label = NULL;
  smp_data->smp_progress_image = NULL;
}

static void otrng_gtk_dialog_free_smp_data(PurpleConversation *conv) {
  SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
  if (!smp_data) {
    return;
  }

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

static SMPData *otrng_gtk_dialog_add_smp_data(PurpleConversation *conv) {
  SMPData *smp_data = malloc(sizeof(SMPData));
  smp_data->smp_secret_dialog = NULL;
  smp_data->smp_secret_smppair = NULL;
  smp_data->smp_progress_dialog = NULL;
  smp_data->smp_progress_bar = NULL;
  smp_data->smp_progress_label = NULL;
  smp_data->smp_progress_image = NULL;
  /* Chosen as initialized value since libotr should never allow
   * this as a "their_instance" value */
  smp_data->their_instance = OTRL_INSTAG_BEST;

  purple_conversation_set_data(conv, "otr-smpdata", smp_data);

  return smp_data;
}

static GtkWidget *otr_icon(GtkWidget *image, TrustLevel level,
                           gboolean sensitivity) {
  const char **data = NULL;

  switch (level) {
  case TRUST_NOT_PRIVATE:
    data = otrng_not_private_icon;
    break;
  case TRUST_UNVERIFIED:
    data = otrng_unverified_icon;
    break;
  case TRUST_PRIVATE:
    data = otrng_private_icon;
    break;
  case TRUST_FINISHED:
    data = otrng_finished_icon;
    break;
  }

  GdkPixbuf *pixbuf = gdk_pixbuf_new_from_xpm_data(data);

  if (image) {
    gtk_image_set_from_pixbuf(GTK_IMAGE(image), pixbuf);
  } else {
    image = gtk_image_new_from_pixbuf(pixbuf);
  }
  g_object_unref(G_OBJECT(pixbuf));

  gtk_widget_set_sensitive(image, sensitivity);

  return image;
}

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget) {
  gtk_widget_destroy(GTK_WIDGET(widget));
}

/* Forward declarations for the benefit of smp_message_response_cb/redraw
 * authvbox */
static void verify_fingerprint(GtkWindow *parent, otrng_client_id_s client_id,
                               otrng_plugin_fingerprint_s *fprint);
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data);
static struct vrfy_fingerprint_data *
vrfy_fingerprint_data_new(otrng_client_id_s client_id,
                          otrng_plugin_fingerprint_s *fprint);
static void vrfy_fingerprint_destroyed(GtkWidget *w,
                                       vrfy_fingerprint_data *vfd);
static void conversation_switched(PurpleConversation *conv, void *data);

static GtkWidget *
create_smp_progress_dialog(GtkWindow *parent,
                           const otrng_plugin_conversation *conv);

static int plugin_fingerprint_get_trusted(otrng_plugin_fingerprint_s *fprint) {
  if (fprint->version == 3) {
    return fprint->v3->fp->trust && fprint->v3->fp->trust[0];
  }
  return fprint->v4->trusted;
}

static void plugin_fingerprint_set_trust(otrng_plugin_fingerprint_s *fprint,
                                         int trust) {
  if (fprint->version == 3) {
    otrl_context_set_trust(fprint->v3->fp, trust ? "verified" : "");
  } else {
    fprint->v4->trusted = trust;
  }
}

/* Called when a button is pressed on the "progress bar" smp dialog */
static void smp_progress_response_cb(GtkDialog *dialog, gint response,
                                     otrng_plugin_conversation *context) {
  PurpleConversation *conv =
      otrng_plugin_conversation_to_purple_conv(context, 0);
  SMPData *smp_data = NULL;

  if (conv) {
    gdouble frac;

    smp_data = purple_conversation_get_data(conv, "otr-smpdata");
    frac = gtk_progress_bar_get_fraction(
        GTK_PROGRESS_BAR(smp_data->smp_progress_bar));

    if (frac != 0.0 && frac != 1.0 && response == GTK_RESPONSE_REJECT) {
      otrng_plugin_abort_smp(context);
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

  otrng_plugin_conversation_free(context);
}

static int start_or_continue_smp(SmpResponsePair *smppair) {
  GtkEntry *question_entry = smppair->question_entry;
  GtkEntry *entry = smppair->entry;

  const char *user_question = NULL;
  char *secret = NULL;
  size_t secret_len = 0;

  secret = g_strdup(gtk_entry_get_text(entry));
  secret_len = strlen(secret);

  if (!smppair->responder) {
    if (smppair->smp_type == AUTH_SMP_QUESTION) {
      if (!question_entry) {
        g_free(secret);
        return 1;
      }

      user_question = gtk_entry_get_text(question_entry);

      if (user_question == NULL || strlen(user_question) == 0) {
        g_free(secret);
        return 1;
      }
    }

    /* pass user question here */
    if (!user_question) {
      otrng_plugin_start_smp(smppair->conv,
                             (const unsigned char *)user_question, 0,
                             (const unsigned char *)secret, secret_len);
    } else {
      otrng_plugin_start_smp(
          smppair->conv, (const unsigned char *)user_question,
          strlen(user_question), (const unsigned char *)secret, secret_len);
    }
  } else {
    otrng_plugin_continue_smp(smppair->conv, (const unsigned char *)secret,
                              secret_len);
  }

  g_free(secret);
  return 0;
}

/* Called when a button is pressed on the "enter the secret" smp dialog
 * The data passed contains a pointer to the text entry field containing
 * the entered secret as well as the current context.
 */
static void smp_secret_response_cb(GtkDialog *dialog, gint response,
                                   AuthSignalData *auth_opt_data) {
  otrng_plugin_conversation *plugin_conv;
  PurpleConversation *conv;
  SMPData *smp_data;
  SmpResponsePair *smppair;

  if (!auth_opt_data) {
    return;
  }

  smppair = auth_opt_data->smppair;

  if (!smppair) {
    return;
  }

  plugin_conv = smppair->conv;

  conv = otrng_plugin_conversation_to_purple_conv(plugin_conv, 1);
  otrng_conversation_s *otr_conv =
      purple_conversation_to_otrng_conversation(conv);

  if (response == GTK_RESPONSE_ACCEPT && smppair->entry) {
    if (!otrng_conversation_is_encrypted(otr_conv)) {
      return;
    }

    if (start_or_continue_smp(smppair)) {
      return;
    }

    /* launch progress bar window */
    create_smp_progress_dialog(GTK_WINDOW(dialog), smppair->conv);
  } else if (response == GTK_RESPONSE_ACCEPT && smppair->vfd) {
    int oldtrust;
    otrng_plugin_fingerprint_s *fprint;

    fprint = smppair->vfd->fprint;

    if (fprint == NULL) {
      return;
    }

    oldtrust = plugin_fingerprint_get_trusted(fprint);
    if (smppair->vfd->newtrust != oldtrust) {
      plugin_fingerprint_set_trust(fprint, smppair->vfd->newtrust);

      /* Write the new info to disk, redraw the ui, and redraw the
       * OTR buttons. */
      otrng_plugin_write_fingerprints();
      otrng_ui_update_keylist();
      otrng_dialog_resensitize_all();
    }
  } else {
    otrng_plugin_abort_smp(smppair->conv);
  }

  gtk_widget_destroy(GTK_WIDGET(dialog));

  /* Clean up references to this window */
  smp_data = purple_conversation_get_data(conv, "otr-smpdata");

  if (smp_data) {
    smp_data->smp_secret_dialog = NULL;
    smp_data->smp_secret_smppair = NULL;
  }

  /* Free memory */
  free(auth_opt_data);
  otrng_plugin_conversation_free(smppair->conv);
  free(smppair);
}

static void close_smp_window(PurpleConversation *conv) {
  SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");
  if (smp_data && smp_data->smp_secret_dialog) {
    gtk_dialog_response(GTK_DIALOG(smp_data->smp_secret_dialog),
                        GTK_RESPONSE_REJECT);
  }
}

static GtkWidget *
create_dialog(GtkWindow *parent, PurpleNotifyMsgType type, const char *title,
              const char *primary, const char *secondary, int sensitive,
              GtkWidget **labelp,
              void (*add_custom)(GtkWidget *vbox, void *data),
              void *add_custom_data,
              void (*custom_response)(GtkDialog *dialog, gint id, void *data),
              void *custom_response_data) {
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
    img = gtk_image_new_from_stock(
        icon_name, gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
  }

  dialog =
      gtk_dialog_new_with_buttons(title ? title : PIDGIN_ALERT_TITLE, parent, 0,
                                  GTK_STOCK_OK, GTK_RESPONSE_ACCEPT, NULL);

  gtk_window_set_focus_on_map(GTK_WINDOW(dialog), FALSE);
  gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

  if (custom_response != NULL) {
    g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(custom_response),
                     custom_response_data);
  } else {
    g_signal_connect(G_OBJECT(dialog), "response",
                     G_CALLBACK(message_response_cb), dialog);
  }
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

  label_text =
      g_strdup_printf("<span weight=\"bold\" size=\"larger\">%s</span>%s%s",
                      (primary ? primary : ""), (primary ? "\n\n" : ""),
                      (secondary ? secondary : ""));

  label = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(label), label_text);
  gtk_label_set_selectable(GTK_LABEL(label), TRUE);
  g_free(label_text);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
  if (add_custom) {
    add_custom(vbox, add_custom_data);
  }
  gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

  gtk_widget_show_all(dialog);

  if (labelp) {
    *labelp = label;
  }
  return dialog;
}

// TODO: I think we need to make sure we have v3 support for all these dialogs
// as well.

static void add_to_vbox_init_one_way_auth(GtkWidget *vbox,
                                          AuthSignalData *auth_opt_data,
                                          const char *question) {
  GtkWidget *question_entry;
  GtkWidget *entry;
  GtkWidget *label;
  GtkWidget *label2 = NULL;
  char *label_text;
  char *label_text_2;

  SmpResponsePair *smppair = auth_opt_data->smppair;

  if (smppair->responder) {
    label_text = g_strdup_printf(
        "<small>\n%s\n</small>",
        _("Your buddy is attempting to determine if they are really "
          "talking to you, or if it's someone pretending to be you.  "
          "Your buddy has asked the question indicated below.  "
          "To authenticate to your buddy, enter the answer and then "
          "click OK."));
  } else {
    label_text = g_strdup_printf(
        "<small>\n%s\n</small>",
        _("To authenticate using a question, pick a question whose "
          "answer is known only to you and your buddy. Enter this "
          "question and this answer and then wait for your buddy to "
          "enter the answer too. If the answers "
          "don't match, then you may be talking to an imposter."));
  }

  label = gtk_label_new(NULL);

  gtk_label_set_markup(GTK_LABEL(label), label_text);
  gtk_label_set_selectable(GTK_LABEL(label), FALSE);
  g_free(label_text);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

  otrng_known_fingerprint_s *fp =
      otrng_plugin_fingerprint_get_active(smppair->conv);

  if (fp && fp->trusted && !(smppair->responder)) {
    label_text_2 = g_strdup_printf("<b>\n%s\n</b>",
                                   _("This buddy is already authenticated."));
    label2 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label2), label_text_2);

    gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
  }

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
    label_text = g_markup_printf_escaped(
        "<span background=\"white\" "
        "foreground=\"black\" weight=\"bold\">%s</span>",
        question);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    smppair->question_entry = NULL;
  } else {
    /* Create the text view where the user enters their question */
    question_entry = gtk_entry_new();
    smppair->question_entry = GTK_ENTRY(question_entry);
    gtk_box_pack_start(GTK_BOX(vbox), question_entry, FALSE, FALSE, 0);
  }

  /* Leave a blank line */
  gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);

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
  gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
}

static void add_to_vbox_init_two_way_auth(GtkWidget *vbox,
                                          AuthSignalData *auth_opt_data) {
  GtkWidget *entry;
  GtkWidget *label;
  GtkWidget *label2 = NULL;
  char *label_text;
  char *label_text_2;

  label_text = g_strdup_printf(
      "<small>\n%s\n</small>",
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

  otrng_known_fingerprint_s *fp =
      otrng_plugin_fingerprint_get_active(auth_opt_data->smppair->conv);
  if (fp && fp->trusted) {
    label_text_2 = g_strdup_printf("<b>\n%s\n</b>",
                                   _("This buddy is already authenticated."));
    label2 = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label2), label_text_2);

    gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
  }

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

  gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
}

static char *create_verify_fingerprint_label_v3(
    const otrng_known_fingerprint_v3_s *other_fprint, const char *protocol,
    const char *account) {
  char our_human_fprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
  char other_human_fprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
  PurplePlugin *p;
  char *proto_name;
  char *label_text;

  strncpy(our_human_fprint, _("[none]"), OTRL_PRIVKEY_FPRINT_HUMAN_LEN - 1);

  otrl_privkey_fingerprint(otrng_state->user_state_v3, our_human_fprint,
                           account, protocol);

  p = purple_find_prpl(protocol);
  proto_name = (p && p->info->name) ? p->info->name : _("Unknown");

  otrl_privkey_hash_to_human(other_human_fprint, other_fprint->fp->fingerprint);

  label_text = g_strdup_printf(_("Fingerprint for you, %s (%s):\n%s\n\n"
                                 "Purported fingerprint for %s:\n%s\n"),
                               account, proto_name, our_human_fprint,
                               other_fprint->username, other_human_fprint);

  return label_text;
}

static char *create_verify_fingerprint_label_v4(
    const otrng_known_fingerprint_s *their_fprint, const char *protocol,
    const char *account) {
  char our_human_fprint[OTRNG_FPRINT_HUMAN_LEN];
  char their_human_fprint[OTRNG_FPRINT_HUMAN_LEN];
  PurplePlugin *p;
  char *proto_name;
  char *label_text;

  strncpy(our_human_fprint, _("[none]"), OTRNG_FPRINT_HUMAN_LEN - 1);

  otrng_client_s *client = get_otrng_client(protocol, account);
  char *our_fp_human_tmp = otrv4_client_adapter_privkey_fingerprint(client);
  if (our_fp_human_tmp) {
    strncpy(our_human_fprint, our_fp_human_tmp, OTRNG_FPRINT_HUMAN_LEN);
  }
  free(our_fp_human_tmp);

  p = purple_find_prpl(protocol);
  proto_name = (p && p->info->name) ? p->info->name : _("Unknown");

  otrng_fingerprint_hash_to_human(their_human_fprint, their_fprint->fp,
                                  sizeof(their_fprint->fp));

  label_text = g_strdup_printf(_("Fingerprint for you, %s (%s):\n%s\n\n"
                                 "Purported fingerprint for %s:\n%s\n"),
                               account, proto_name, our_human_fprint,
                               their_fprint->username, their_human_fprint);

  return label_text;
}

static char *
create_verify_fingerprint_label(const otrng_plugin_fingerprint_s *their_fprint,
                                const char *protocol, const char *account) {
  if (their_fprint->version == 3) {
    return create_verify_fingerprint_label_v3(their_fprint->v3, protocol,
                                              account);
  }
  return create_verify_fingerprint_label_v4(their_fprint->v4, protocol,
                                            account);
}

static otrng_plugin_fingerprint_s *otrng_plugin_fingerprint_new(int version,
                                                                void *data) {
  otrng_plugin_fingerprint_s *fp = malloc(sizeof(otrng_plugin_fingerprint_s));
  fp->version = version;
  if (version == 3) {
    fp->v3 = data;
  } else if (version == 4) {
    fp->v4 = data;
  }
  return fp;
}

static void
add_to_vbox_verify_fingerprint(GtkWidget *vbox,
                               const otrng_plugin_conversation *conv,
                               SmpResponsePair *smppair) {
  GtkWidget *label;
  char *label_text;
  vrfy_fingerprint_data *vfd;
  otrng_plugin_fingerprint_s *fp;

  if (conv->conv->running_version == 3) {
    otrng_known_fingerprint_v3_s *ff;
    Fingerprint *fprint = conv->conv->v3_conn->ctx->active_fingerprint;
    if (fprint == NULL)
      return;
    if (fprint->fingerprint == NULL)
      return;
    ff = malloc(sizeof(otrng_known_fingerprint_v3_s));
    ff->fp = fprint;
    ff->username = conv->conv->v3_conn->ctx->username;
    fp = otrng_plugin_fingerprint_new(3, ff);
  } else {
    otrng_known_fingerprint_s *fprint =
        otrng_plugin_fingerprint_get_active(conv);
    if (fprint == NULL)
      return;
    fp = otrng_plugin_fingerprint_new(4, fprint);
  }

  label_text = g_strdup_printf(
      "<small>\n%s %s\n</small>",
      _("To verify the fingerprint, contact your buddy via some "
        "other authenticated channel, such as the telephone "
        "or GPG-signed email. Each of you should tell your fingerprint "
        "to the other."),
      _("If everything matches up, you should choose the <b>I have</b> option "
        "in the menu below."));

  label = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(label), label_text);
  gtk_label_set_selectable(GTK_LABEL(label), TRUE);
  g_free(label_text);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

  label_text =
      create_verify_fingerprint_label(fp, conv->protocol, conv->account);
  if (label_text == NULL) {
    return;
  }

  label = gtk_label_new(NULL);

  gtk_label_set_markup(GTK_LABEL(label), label_text);
  /* Make the label containing the fingerprints selectable, but
   * not auto-selected. */
  gtk_label_set_selectable(GTK_LABEL(label), TRUE);

  g_free(label_text);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

  vfd = vrfy_fingerprint_data_new(conv->conv->client->client_id, fp);

  smppair->vfd = vfd;

  add_vrfy_fingerprint(vbox, vfd);
  g_signal_connect(G_OBJECT(vbox), "destroy",
                   G_CALLBACK(vrfy_fingerprint_destroyed), vfd);
}

static void redraw_auth_vbox(GtkComboBox *combo, void *data) {
  AuthSignalData *auth_data = (AuthSignalData *)data;

  GtkWidget *notebook = auth_data ? auth_data->notebook : NULL;

  int selected;

  if (auth_data == NULL) {
    return;
  }

  selected = gtk_combo_box_get_active(combo);

  if (selected == 0) {
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);
    auth_data->smppair->entry = auth_data->one_way_entry;
    auth_data->smppair->smp_type = AUTH_SMP_QUESTION;
  } else if (selected == 1) {
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 1);
    auth_data->smppair->entry = auth_data->two_way_entry;
    auth_data->smppair->smp_type = AUTH_SMP_SHARED_SECRET;
  } else if (selected == 2) {
    auth_data->smppair->entry = NULL;
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 2);
    auth_data->smppair->smp_type = AUTH_FINGERPRINT_VERIFICATION;
  }
}

static void add_other_authentication_options(GtkWidget *vbox,
                                             GtkWidget *notebook,
                                             AuthSignalData *data) {
  GtkWidget *label;
  GtkWidget *combo;
  char *labeltext;

  labeltext = g_strdup_printf(
      "\n%s", _("How would you like to authenticate your buddy?"));
  label = gtk_label_new(labeltext);
  g_free(labeltext);
  gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.0);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

  combo = gtk_combo_box_new_text();

  gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("Question and answer"));

  gtk_combo_box_append_text(GTK_COMBO_BOX(combo), _("Shared secret"));

  gtk_combo_box_append_text(GTK_COMBO_BOX(combo),
                            _("Manual fingerprint verification"));

  gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
  gtk_box_pack_start(GTK_BOX(vbox), combo, FALSE, FALSE, 0);

  data->notebook = notebook;

  g_signal_connect(combo, "changed", G_CALLBACK(redraw_auth_vbox), data);
}

static void create_smp_dialog(const char *title, const char *primary,
                              const otrng_plugin_conversation *pconv,
                              gboolean responder, const char *question) {
  GtkWidget *dialog;
  PurpleConversation *conv = otrng_plugin_conversation_to_purple_conv(pconv, 1);

  SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

  close_progress_window(smp_data);

  /* If you start SMP authentication on a different context, it
   * will kill any existing SMP */
  if (smp_data->their_instance != pconv->their_instance_tag) {
    otrng_gtk_dialog_free_smp_data(conv);
    smp_data = otrng_gtk_dialog_add_smp_data(conv);
  }

  if (!(smp_data->smp_secret_dialog)) {
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *auth_vbox;
    GtkWidget *label;
    GtkWidget *img = NULL;
    char *label_text;
    SmpResponsePair *smppair;
    GtkWidget *notebook;
    AuthSignalData *auth_opt_data;

    smppair = malloc(sizeof(SmpResponsePair));
    if (!smppair) {
      return;
    }

    auth_opt_data = malloc(sizeof(AuthSignalData));
    if (!auth_opt_data) {
      free(smppair);
      return;
    }

    smp_data->their_instance = pconv->their_instance_tag;

    dialog = gtk_dialog_new_with_buttons(
        title ? title : PIDGIN_ALERT_TITLE, NULL, 0, GTK_STOCK_CANCEL,
        GTK_RESPONSE_REJECT, _("_Authenticate"), GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);

    auth_vbox = gtk_vbox_new(FALSE, 0);
    hbox = gtk_hbox_new(FALSE, 15);
    vbox = gtk_vbox_new(FALSE, 0);
    notebook = gtk_notebook_new();

    smppair->responder = responder;
    smppair->conv = otrng_plugin_conversation_copy(pconv);
    auth_opt_data->smppair = smppair;

    gtk_window_set_focus_on_map(GTK_WINDOW(dialog), !responder);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    img = gtk_image_new_from_stock(
        PIDGIN_STOCK_DIALOG_AUTH,
        gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);

    label_text =
        g_strdup_printf("<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s",
                        (primary ? primary : ""),
                        _("Authenticating a buddy helps ensure that the person "
                          "you are talking to is who they claim to be."));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), FALSE);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    if (!responder) {
      add_other_authentication_options(vbox, notebook, auth_opt_data);
    }

    g_signal_connect(G_OBJECT(dialog), "response",
                     G_CALLBACK(smp_secret_response_cb), auth_opt_data);

    if (!responder || (responder && question != NULL)) {
      GtkWidget *one_way_vbox = gtk_vbox_new(FALSE, 0);
      add_to_vbox_init_one_way_auth(one_way_vbox, auth_opt_data, question);
      gtk_notebook_append_page(GTK_NOTEBOOK(notebook), one_way_vbox,
                               gtk_label_new("0"));
      smppair->entry = auth_opt_data->one_way_entry;
      smppair->smp_type = AUTH_SMP_QUESTION;
    }

    if (!responder || (responder && question == NULL)) {
      GtkWidget *two_way_vbox = gtk_vbox_new(FALSE, 0);
      add_to_vbox_init_two_way_auth(two_way_vbox, auth_opt_data);
      gtk_notebook_append_page(GTK_NOTEBOOK(notebook), two_way_vbox,
                               gtk_label_new("1"));

      if (responder && question == NULL) {
        smppair->entry = auth_opt_data->two_way_entry;
        smppair->smp_type = AUTH_SMP_SHARED_SECRET;
      }
    }

    if (!responder) {
      GtkWidget *fingerprint_vbox = gtk_vbox_new(FALSE, 0);
      add_to_vbox_verify_fingerprint(fingerprint_vbox, pconv, smppair);
      gtk_notebook_append_page(GTK_NOTEBOOK(notebook), fingerprint_vbox,
                               gtk_label_new("2"));
    }

    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook), FALSE);

    gtk_notebook_set_show_border(GTK_NOTEBOOK(notebook), FALSE);
    gtk_box_pack_start(GTK_BOX(auth_vbox), notebook, FALSE, FALSE, 0);
    gtk_widget_show(notebook);

    gtk_box_pack_start(GTK_BOX(vbox), auth_vbox, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

    gtk_widget_show_all(dialog);

    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), 0);

    if (!responder) {
      gtk_window_set_focus(GTK_WINDOW(dialog),
                           GTK_WIDGET(smppair->question_entry));
    } else {
      gtk_window_set_focus(GTK_WINDOW(dialog), GTK_WIDGET(smppair->entry));
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
}

static GtkWidget *
create_smp_progress_dialog(GtkWindow *parent,
                           const otrng_plugin_conversation *conv) {
  GtkWidget *dialog;
  GtkWidget *hbox;
  GtkWidget *vbox;
  GtkWidget *label;
  GtkWidget *proglabel;
  GtkWidget *bar;
  GtkWidget *progimg = NULL;
  char *label_text, *label_pat;
  const char *icon_name = NULL;
  PurpleConversation *pconv;
  SMPData *smp_data;

  pconv = otrng_plugin_conversation_to_purple_conv(conv, 1);
  PurpleAccount *account = purple_conversation_get_account(pconv);
  char *username =
      g_strdup(purple_normalize(account, purple_conversation_get_name(pconv)));

  // TODO: How to get this?
  // This came from context->smstate->received_question
  int received_question = 0;

  dialog = gtk_dialog_new_with_buttons(
      received_question
          ?
          /* Translators: you are asked to authenticate yourself */
          _("Authenticating to Buddy")
          :
          /* Translators: you asked your buddy to authenticate him/herself */
          _("Authenticating Buddy"),
      NULL, 0, GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, GTK_STOCK_OK,
      GTK_RESPONSE_ACCEPT, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
  gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_REJECT, 1);
  gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT, 0);

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

  gtk_box_pack_start(GTK_BOX(hbox), NULL, FALSE, FALSE, 0);

  label_pat = g_strdup_printf("<span weight=\"bold\" size=\"larger\">"
                              "%s</span>\n",
                              received_question ? _("Authenticating to %s")
                                                : _("Authenticating %s"));
  label_text = g_strdup_printf(label_pat, username);
  free(username);
  g_free(label_pat);

  label = gtk_label_new(NULL);

  gtk_label_set_markup(GTK_LABEL(label), label_text);
  gtk_label_set_selectable(GTK_LABEL(label), TRUE);
  g_free(label_text);
  gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
  gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

  proglabel = gtk_label_new(NULL);
  gtk_label_set_selectable(GTK_LABEL(proglabel), TRUE);
  gtk_label_set_line_wrap(GTK_LABEL(proglabel), TRUE);
  gtk_misc_set_alignment(GTK_MISC(proglabel), 0, 0);
  gtk_box_pack_start(GTK_BOX(vbox), proglabel, FALSE, FALSE, 0);

  icon_name = PIDGIN_STOCK_DIALOG_INFO;
  progimg = gtk_image_new_from_stock(
      icon_name, gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
  gtk_misc_set_alignment(GTK_MISC(progimg), 0, 0);

  gtk_box_pack_start(GTK_BOX(hbox), progimg, FALSE, FALSE, 0);

  /* Create the progress bar */
  bar = gtk_progress_bar_new();
  gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), 0.1);
  gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

  gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

  smp_data = purple_conversation_get_data(pconv, "otr-smpdata");
  if (smp_data) {
    smp_data->smp_progress_dialog = dialog;
    smp_data->smp_progress_bar = bar;
    smp_data->smp_progress_label = proglabel;
    smp_data->smp_progress_image = progimg;
  }

  gtk_label_set_text(GTK_LABEL(proglabel), _("Waiting for buddy..."));

  gtk_image_set_from_stock(
      GTK_IMAGE(smp_data->smp_progress_image), PIDGIN_STOCK_DIALOG_AUTH,
      gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));

  g_signal_connect(G_OBJECT(dialog), "response",
                   G_CALLBACK(smp_progress_response_cb),
                   otrng_plugin_conversation_copy(conv));

  gtk_widget_show_all(dialog);

  return dialog;
}

/* This is just like purple_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
static void
otrng_gtk_dialog_notify_message(PurpleNotifyMsgType type,
                                const char *accountname, const char *protocol,
                                const char *username, const char *title,
                                const char *primary, const char *secondary) {
  create_dialog(NULL, type, title, primary, secondary, 1, NULL, NULL, NULL,
                NULL, NULL);
}

struct s_OtrgDialogWait {
  GtkWidget *dialog;
  GtkWidget *label;
};

/* Put up a Please Wait dialog, with the "OK" button desensitized.
 * Return a handle that must eventually be passed to
 * otrng_dialog_private_key_wait_done. */
static OtrgDialogWaitHandle
otrng_gtk_dialog_private_key_wait_start(const char *account,
                                        const char *protocol) {
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
                         secondary, 0, &label, NULL, NULL, NULL, NULL);
  handle = malloc(sizeof(struct s_OtrgDialogWait));
  handle->dialog = dialog;
  handle->label = label;

  /* Make sure the dialog is actually displayed before doing any
   * compute-intensive stuff. */
  while (gtk_events_pending()) {
    gtk_main_iteration();
  }

  g_free(secondary);

  return handle;
}

static int otrng_gtk_dialog_display_otr_message(const char *accountname,
                                                const char *protocol,
                                                const char *username,
                                                const char *msg,
                                                int force_create) {
  /* See if there's a conversation window we can put this in. */
  PurpleConversation *conv = otrng_plugin_userinfo_to_conv(
      accountname, protocol, username, force_create);

  if (!conv) {
    return -1;
  }

  purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));

  return 0;
}

/* End a Please Wait dialog. */
static void
otrng_gtk_dialog_private_key_wait_done(OtrgDialogWaitHandle handle) {
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
static void
otrng_gtk_dialog_unknown_fingerprint(OtrlUserState us, const char *accountname,
                                     const char *protocol, const char *who,
                                     const unsigned char fingerprint[20]) {
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
    while (fp) {
      // TODO: this need sto be fixed for checking against new style OTRNG
      // fingerprints
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
                            "computer.  You should authenticate "
                            "this buddy."),
                          who);
  } else {
    buf = g_strdup_printf(_("%s has not been authenticated yet.  You "
                            "should authenticate this buddy."),
                          who);
  }

  conv = otrng_plugin_userinfo_to_conv(accountname, protocol, who, TRUE);

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  g_free(buf);
}

static void otrng_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void build_otr_menu(PurpleConversation *conv, GtkWidget *menu,
                           TrustLevel level);
static void otr_refresh_otr_buttons(PurpleConversation *conv);
static void otr_destroy_top_menu_objects(PurpleConversation *conv);
static void otr_add_top_otr_menu(PurpleConversation *conv);

static void destroy_menuitem(GtkWidget *widget, gpointer data) {
  gtk_widget_destroy(widget);
}

static void otr_build_status_submenu(PidginWindow *win,
                                     const ConvOrContext *convctx,
                                     GtkWidget *menu, TrustLevel level);

static void otr_check_conv_status_change(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);

  TrustLevel current_level = TRUST_NOT_PRIVATE;
  TrustLevel *previous_level = NULL;

  char *buf = NULL;
  char *status = "";
  int level = -1;

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  current_level = otrng_plugin_conversation_to_trust(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);

  previous_level = (TrustLevel *)g_hash_table_lookup(otr_win_status, gtkconv);

  /** Not show the message for an unchanged status */
  if (previous_level && *previous_level == current_level) {
    return;
  }

  buf = _("The privacy status of the current conversation is: "
          "<a href=\"viewstatus:%d\">%s</a>");

  switch (current_level) {
  case TRUST_NOT_PRIVATE:
    status = _("Not Private");
    level = 0;
    break;
  case TRUST_UNVERIFIED:
    status = _("Unverified");
    level = 1;
    break;
  case TRUST_PRIVATE:
    status = _("Private");
    level = 2;
    break;
  case TRUST_FINISHED:
    status = _("Finished");
    level = 3;
    break;
  }

  buf = g_strdup_printf(buf, level, status);

  if (previous_level) {
    /* Write a new message indicating the level change.
     * The timestamp image will be appended as the message
     * timestamp signal is caught, which will also update
     * the privacy level for this gtkconv */
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM,
                              time(NULL));
  }

  if (conv == gtkconv->active_conv) {
    /* 'free' is handled by the hashtable */
    TrustLevel *current_level_ptr = malloc(sizeof(TrustLevel));

    if (!current_level_ptr) {
      g_free(buf);
      return;
    }

    *current_level_ptr = current_level;
    g_hash_table_replace(otr_win_status, gtkconv, current_level_ptr);
  }

  g_free(buf);
}

static void dialog_update_label_conv(PurpleConversation *conv,
                                     TrustLevel level) {
  GtkWidget *label;
  GtkWidget *icon;
  GtkWidget *button;
  GtkWidget *menu;
  ConvOrContext *convctx;
  GHashTable *conv_or_ctx_map;
  char *markup;
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  label = purple_conversation_get_data(conv, "otr-label");
  icon = purple_conversation_get_data(conv, "otr-icon");
  button = purple_conversation_get_data(conv, "otr-button");
  menu = purple_conversation_get_data(conv, "otr-menu");

  otr_icon(icon, level, 1);
  markup = g_strdup_printf(
      " <span color=\"%s\">%s</span>",
      level == TRUST_FINISHED
          ? "#000000"
          : level == TRUST_PRIVATE
                ? "#00a000"
                : level == TRUST_UNVERIFIED ? "#a06000" : "#ff0000",
      level == TRUST_FINISHED
          ? _("Finished")
          : level == TRUST_PRIVATE
                ? _("Private")
                : level == TRUST_UNVERIFIED ? _("Unverified")
                                            : _("Not private"));
  gtk_label_set_markup(GTK_LABEL(label), markup);
  g_free(markup);
  gtk_tooltips_set_tip(gtkconv->tooltips, button, _("OTR Status"), NULL);

  /* Use any non-NULL value for "private", NULL for "not private" */
  purple_conversation_set_data(
      conv, "otr-private",
      (level == TRUST_NOT_PRIVATE || level == TRUST_FINISHED) ? NULL : conv);

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

  build_otr_menu(conv, menu, level); // TODO: first call to build_otr_menu
  otr_build_status_submenu(pidgin_conv_get_window(gtkconv), convctx, menu,
                           level);

  conv = gtkconv->active_conv;
  otr_check_conv_status_change(conv);

  /* Update other widgets */
  if (gtkconv != pidgin_conv_window_get_active_gtkconv(gtkconv->win)) {
    return;
  }

  otr_destroy_top_menu_objects(conv); // TODO: second call to build_otr_menu.
  otr_add_top_otr_menu(conv);
  otr_refresh_otr_buttons(conv);
}

static void dialog_update_label_real(const otrng_plugin_conversation *context) {
  PurpleAccount *account;
  PurpleConversation *conv;

  TrustLevel level = otrng_plugin_conversation_to_trust(context);

  account = purple_accounts_find(context->account, context->protocol);
  if (!account) {
    return;
  }
  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
                                               context->peer, account);
  if (!conv) {
    return;
  }

  dialog_update_label_conv(conv, level);
}

static char *
plugin_fingerprint_get_username(otrng_plugin_fingerprint_s *fprint) {
  if (fprint->version == 3) {
    return fprint->v3->username;
  }
  return fprint->v4->username;
}

static otrng_plugin_conversation *
conn_context_to_plugin_conversation(ConnContext *context) {
  if (!context) {
    return NULL;
  }

  otrng_plugin_conversation *plugin_conv =
      malloc(sizeof(otrng_plugin_conversation));
  if (!plugin_conv) {
    return NULL;
  }

  plugin_conv->account = context->accountname;
  plugin_conv->protocol = context->protocol;
  plugin_conv->peer = context->username;

  return plugin_conv;
}

static void vrfy_fingerprint_data_free(struct vrfy_fingerprint_data *vfd) {
  free(vfd->accountname);
  free(vfd->protocol);
  free(vfd->fprint);
  free(vfd);
}

static vrfy_fingerprint_data *
vrfy_fingerprint_data_new(otrng_client_id_s client_id,
                          otrng_plugin_fingerprint_s *fprint) {
  vrfy_fingerprint_data *vfd;

  vfd = malloc(sizeof(vrfy_fingerprint_data));
  vfd->fprint = fprint;
  vfd->accountname = strdup(client_id.account);
  vfd->protocol = strdup(client_id.protocol);
  // TODO: Why do you need their instance tag?
  // vfd->their_instance = context->their_instance;

  return vfd;
}

static void vrfy_fingerprint_destroyed(GtkWidget *w,
                                       struct vrfy_fingerprint_data *vfd) {
  vrfy_fingerprint_data_free(vfd);
}

static void vrfy_fingerprint_changed(GtkComboBox *combo, void *data) {
  vrfy_fingerprint_data *vfd = data;
  int trust = gtk_combo_box_get_active(combo) == 1 ? 1 : 0;
  vfd->newtrust = trust;
}

/* Add the verify widget and the help text for the verify fingerprint box. */
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data) {
  GtkWidget *hbox;
  GtkWidget *combo, *label;
  vrfy_fingerprint_data *vfd = data;
  char *labelt;
  int verified = plugin_fingerprint_get_trusted(vfd->fprint);

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
                           plugin_fingerprint_get_username(vfd->fprint));
  label = gtk_label_new(labelt);
  g_free(labelt);
  gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

  /* Leave a blank line */
  gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);
}

static void verify_fingerprint_response_cb(GtkDialog *dialog, gint response,
                                           void *data) {
  vrfy_fingerprint_data *vfd = data;
  if (response == GTK_RESPONSE_ACCEPT) {
    int oldtrust;
    otrng_plugin_fingerprint_s *fprint = vfd->fprint;

    if (fprint == NULL) {
      return;
    }

    oldtrust = plugin_fingerprint_get_trusted(fprint);
    if (vfd->newtrust != oldtrust) {
      plugin_fingerprint_set_trust(fprint, vfd->newtrust);

      /* Write the new info to disk, redraw the ui, and redraw the
       * OTR buttons. */
      otrng_plugin_write_fingerprints();
      otrng_ui_update_keylist();
      otrng_dialog_resensitize_all();
    }
  }
  gtk_widget_destroy(GTK_WIDGET(dialog));
}

static void verify_fingerprint(GtkWindow *parent, otrng_client_id_s client_id,
                               otrng_plugin_fingerprint_s *fprint) {
  GtkWidget *dialog;
  char *primary;
  char *secondary;
  vrfy_fingerprint_data *vfd;

  if (fprint == NULL) {
    return;
  }

  primary = g_strdup_printf(_("Verify fingerprint for %s"),
                            plugin_fingerprint_get_username(fprint));

  char *label_fpr = create_verify_fingerprint_label(fprint, client_id.protocol,
                                                    client_id.account);
  secondary = g_strdup_printf(
      _("<small><i>%s %s\n\n</i></small>"
        "%s"),
      _("To verify the fingerprint, contact your buddy via some "
        "<i>other</i> authenticated channel, such as the telephone "
        "or GPG-signed email.  Each of you should tell your fingerprint "
        "to the other."),
      _("If everything matches up, you should indicate in the above "
        "dialog that you <b>have</b> verified the fingerprint."),
      label_fpr);
  g_free(label_fpr);

  vfd = vrfy_fingerprint_data_new(client_id, fprint);
  dialog =
      create_dialog(parent, PURPLE_NOTIFY_MSG_INFO, _("Verify fingerprint"),
                    primary, secondary, 1, NULL, add_vrfy_fingerprint, vfd,
                    verify_fingerprint_response_cb, vfd);
  g_signal_connect(G_OBJECT(dialog), "destroy",
                   G_CALLBACK(vrfy_fingerprint_destroyed), vfd);

  g_free(primary);
  g_free(secondary);
}

static void
otrng_gtk_dialog_verify_fingerprint(otrng_client_id_s client_id,
                                    otrng_plugin_fingerprint_s *fprint) {
  verify_fingerprint(NULL, client_id, fprint);
}

/* Create the SMP dialog.  responder is true if this is called in
 * response to someone else's run of SMP. */
static void
otrng_gtk_dialog_socialist_millionaires(const otrng_plugin_conversation *conv,
                                        const char *question,
                                        gboolean responder) {
  char *primary;

  if (conv == NULL) {
    return;
  }

  if (responder && question) {
    primary = g_strdup_printf(_("Authentication from %s"), conv->peer);
  } else {
    primary = g_strdup_printf(_("Authenticate %s"), conv->peer);
  }

  create_smp_dialog(_("Authenticate Buddy"), primary, conv, responder,
                    question);

  g_free(primary);
}

/* Call this to update the status of an ongoing socialist millionaires
 * protocol.  Progress_level is a percentage, from 0.0 (aborted) to
 * 1.0 (complete).  Any other value represents an intermediate state. */
static void
otrng_gtk_dialog_update_smp(const otrng_plugin_conversation *context,
                            otrng_smp_event smp_event, double progress_level) {
  PurpleConversation *conv =
      otrng_plugin_conversation_to_purple_conv(context, 0);
  GtkProgressBar *bar;
  SMPData *smp_data = purple_conversation_get_data(conv, "otr-smpdata");

  if (!smp_data) {
    return;
  }

  bar = GTK_PROGRESS_BAR(smp_data->smp_progress_bar);
  gtk_progress_bar_set_fraction(bar, progress_level);

  /* If the counter is reset to absolute zero, the protocol has aborted */
  if (progress_level == 0.0) {
    GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

    gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
    gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);

    gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
                       _("An error occurred during authentication."));
    gtk_image_set_from_stock(
        GTK_IMAGE(smp_data->smp_progress_image), PIDGIN_STOCK_DIALOG_ERROR,
        gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    return;
  }
  if (progress_level == 1.0) {
    /* If the counter reaches 1.0, the protocol is complete */
    GtkDialog *dialog = GTK_DIALOG(smp_data->smp_progress_dialog);

    gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_ACCEPT, 1);
    gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_REJECT, 0);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);

    if (smp_event == OTRNG_SMP_EVENT_SUCCESS) {
      // TODO: This is how it used to behave:
      //- It expects the libotr to set trust on on the fingerprint.
      //- It expects both parties to run different SMPs to authenticate
      // each other, and not allow a single SMP to authenticate both.
      int responder = 0; // TODO: How can we know it now? We cant use
      // smp_data->smp_secret_smppair->responder (its is not available)
      otrng_known_fingerprint_s *fp =
          otrng_plugin_fingerprint_get_active(context);
      if (fp && !responder) {
        fp->trusted = otrng_true;
        otrng_plugin_write_fingerprints();
        otrng_ui_update_keylist();
        otrng_dialog_resensitize_all();
      }

      if (fp && fp->trusted) {
        gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
                           _("Authentication successful."));
        gtk_image_set_from_stock(
            GTK_IMAGE(smp_data->smp_progress_image), PIDGIN_STOCK_DIALOG_INFO,
            gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
      } else {
        gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
                           _("Your buddy has successfully authenticated you.  "
                             "You may want to authenticate your buddy as "
                             "well by asking your own question."));
      }
    } else {
      gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label),
                         _("Authentication failed."));
      gtk_image_set_from_stock(
          GTK_IMAGE(smp_data->smp_progress_image), PIDGIN_STOCK_DIALOG_ERROR,
          gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_HUGE));
    }
  } else {
    /* Clear the progress label */
    gtk_label_set_text(GTK_LABEL(smp_data->smp_progress_label), "");
  }
}

/* Call this when a context transitions to ENCRYPTED. */
static void
otrng_gtk_dialog_connected_real(const otrng_plugin_conversation *context) {
  PurpleConversation *conv;
  char *buf;
  char *format_buf;
  TrustLevel level;
  OtrgUiPrefs prefs;
  gboolean *is_multi_inst;
  int protocol_version;
  char *ssid = NULL;
  uint8_t emptySSID[SSID_BYTES] = {0};

  conv = otrng_plugin_conversation_to_purple_conv(context, TRUE);
  level = otrng_plugin_conversation_to_trust(context);
  protocol_version = otrng_plugin_conversation_to_protocol_version(context);

  otrng_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
                     context->peer);
  if (prefs.avoid_logging_otr) {
    purple_conversation_set_logging(conv, FALSE);
  }

  switch (level) {
  case TRUST_PRIVATE:
    format_buf = g_strdup(_("Private conversation started.%s%s"));
    break;

  case TRUST_UNVERIFIED:
    format_buf = g_strdup_printf(_("Unverified "
                                   "conversation started.%%s%%s"));
    break;

  default:
    /* This last case should never happen, since we know
     * we're in ENCRYPTED. */
    format_buf = g_strdup(_("Not private conversation started.%s%s"));
    break;
  }

  buf = g_strdup_printf(
      format_buf,
      protocol_version == 1 ? _("  Warning: using old "
                                "protocol version 1.")
                            : "",
      conv->logging ? _("  Your client is logging this conversation.")
                    : _("  Your client is not logging this conversation."));

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  g_free(buf);
  g_free(format_buf);

  // Get the SSID and show as another line in the conversation window
  otrng_conversation_s *otr_conv =
      purple_conversation_to_otrng_conversation(conv);

  if (memcmp(otr_conv->conn->keys->ssid, emptySSID, 8) != 0 &&
      purple_prefs_get_bool("/OTR/showssidbutton")) {
    if (otr_conv->conn->keys->ssid_half_first) {
      ssid = _("The <a href=\"ssid\">SSID</a> for this conversation is: "
               "<b>%02X%02X%02X%02X</b> %02X%02X%02X%02X");
    } else {
      ssid = _("The <a href=\"ssid\">SSID</a> for this conversation is: "
               "%02X%02X%02X%02X <b>%02X%02X%02X%02X</b>");
    }

    ssid = g_strdup_printf(
        ssid, otr_conv->conn->keys->ssid[0], otr_conv->conn->keys->ssid[1],
        otr_conv->conn->keys->ssid[2], otr_conv->conn->keys->ssid[3],
        otr_conv->conn->keys->ssid[4], otr_conv->conn->keys->ssid[5],
        otr_conv->conn->keys->ssid[6], otr_conv->conn->keys->ssid[7]);

    purple_conversation_write(conv, NULL, ssid, PURPLE_MESSAGE_RAW, time(NULL));

    g_free(ssid);
  }

  dialog_update_label_real(context);

  is_multi_inst = (gboolean *)purple_conversation_get_data(
      conv, "otr-conv_multi_instances");

  if (is_multi_inst && *is_multi_inst) {
    gboolean *have_warned_instances =
        (gboolean *)purple_conversation_get_data(conv, "otr-warned_instances");

    if (have_warned_instances && !*have_warned_instances) {
      *have_warned_instances = TRUE;
      buf = g_strdup_printf(
          _("Your buddy is logged in multiple times and"
            " OTR has established multiple sessions."
            " Use the icon menu above if you wish to select the "
            "outgoing session."));
      otrng_gtk_dialog_display_otr_message(context->account, context->protocol,
                                           context->peer, buf, 0);
      g_free(buf);
    }
  }

  otrng_ui_update_keylist();
  otrng_dialog_resensitize_all();
}

/* Call this when a context transitions to PLAINTEXT. */
static void
otrng_gtk_dialog_disconnected_real(const otrng_plugin_conversation *context) {
  PurpleConversation *conv;
  char *buf;
  OtrgUiPrefs prefs;

  conv = otrng_plugin_conversation_to_purple_conv(context, TRUE);

  buf = _("Private conversation lost.");

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  /*TODO: check if free(buf) is needed*/

  otrng_ui_get_prefs(&prefs, purple_conversation_get_account(conv),
                     context->peer);
  if (prefs.avoid_logging_otr) {
    if (purple_prefs_get_bool("/purple/logging/log_ims")) {
      purple_conversation_set_logging(conv, TRUE);
    }
  }

  dialog_update_label_real(context);
  close_smp_window(conv);

  otrng_ui_update_keylist();
  otrng_dialog_resensitize_all();
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
static void otrng_gtk_dialog_finished(const char *accountname,
                                      const char *protocol,
                                      const char *username) {
  /* See if there's a conversation window we can put this in. */
  PurpleAccount *account;
  PurpleConversation *conv;
  char *buf;

  account = purple_accounts_find(accountname, protocol);
  if (!account) {
    return;
  }

  conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username,
                                               account);
  if (!conv) {
    return;
  }

  // This purple_normalize is safe without g_strdup
  buf = g_strdup_printf(
      _("%s has ended his/her private conversation with "
        "you; you should do the same."),
      purple_normalize(account, purple_conversation_get_name(conv)));

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  g_free(buf);

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  TrustLevel level = otrng_plugin_conversation_to_trust(plugin_conv);
  free(plugin_conv);

  dialog_update_label_conv(conv, level);
  close_smp_window(conv);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrng_gtk_dialog_stillconnected(ConnContext *context) {
  PurpleConversation *conv;
  char *buf;
  char *format_buf;

  otrng_plugin_conversation *plugin_conv =
      conn_context_to_plugin_conversation(context);
  TrustLevel level = otrng_plugin_conversation_to_trust(plugin_conv);

  conv = otrng_plugin_context_to_conv(context, 1);

  switch (level) {
  case TRUST_PRIVATE:
    format_buf = g_strdup(_("Successfully refreshed the private "
                            "conversation with %s.%s"));
    break;

  case TRUST_UNVERIFIED:
    format_buf = g_strdup_printf(_("Successfully refreshed the "
                                   "unverified conversation with "
                                   "%%s.%%s"));
    break;

  default:
    /* This last case should never happen, since we know
     * we're in ENCRYPTED. */
    format_buf = g_strdup(_("Successfully refreshed the not private "
                            "conversation with %s.%s"));
    break;
  }

  PurpleAccount *account = purple_conversation_get_account(conv);
  char *username =
      g_strdup(purple_normalize(account, purple_conversation_get_name(conv)));
  buf =
      g_strdup_printf(format_buf, username,
                      context->protocol_version == 1 ? _("  Warning: using old "
                                                         "protocol version 1.")
                                                     : "");
  free(username);

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  g_free(buf);
  g_free(format_buf);

  dialog_update_label_real(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);
}

/* This is called when the OTR button in the button box is clicked, or
 * when the appropriate context menu item is selected. */
static void otrng_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data) {
  char *buf;

  PurpleConversation *conv = data;
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);

  if (gtkconv->active_conv != conv) {
    pidgin_conv_switch_active_conversation(conv);
  }

  if (purple_conversation_get_data(conv, "otr-private")) {
    buf = _("Attempting to refresh the private conversation");
  } else {
    buf = _("Attempting to start a private conversation");
  }

  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
  /*TODO: check if free(buf) is needed*/

  PurpleAccount *account = purple_conversation_get_account(conv);
  char *peer =
      g_strdup(purple_normalize(account, purple_conversation_get_name(conv)));

  otrng_client_s *client = purple_account_to_otrng_client(account);
  if (!client) {
    free(peer);
    return;
  }

  otrng_conversation_s *otr_conv =
      otrng_client_get_conversation(0, peer, client);

  /* Don't send if we're already ENCRYPTED */
  // TODO: Implement the "Refresh private conversation" behavior
  if (otrng_conversation_is_encrypted(otr_conv)) {
    free(peer);
    return;
  }

  PurpleBuddy *buddy = purple_find_buddy(account, peer);
  if (otrng_plugin_buddy_is_offline(account, buddy)) {
    otrng_plugin_send_non_interactive_auth(peer, account);
    free(peer);
    return;
  }
  free(peer);

  otrng_plugin_send_default_query_conv(conv);
}

/* Called when SMP verification option selected from menu */
static void socialist_millionaires(GtkWidget *widget, gpointer data) {
  const PurpleConversation *conv = data;

  otrng_conversation_s *otr_conv =
      purple_conversation_to_otrng_conversation(conv);

  if (!otrng_conversation_is_encrypted(otr_conv)) {
    return;
  }

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  otrng_gtk_dialog_socialist_millionaires(plugin_conv, NULL, FALSE);
  otrng_plugin_conversation_free(plugin_conv);
}

static void destroy_dialog_cb(GtkDialog *dialog, gint response) {
  gtk_widget_destroy(GTK_WIDGET(dialog));
}

static gchar *get_text_main() {
  gchar *text;

  text = g_strdup_printf(
      "<span weight=\"bold\" size=\"larger\">%s</span>\n\n%s\n\n%s <i>%s</i> "
      "%s\n\n%s",
      "Understanding OTRv4",
      "OTRv4 is the fourth version of the Off-the-Record Protocol.", "OTRng",
      "-the plugin you are using-",
      "is the plugin that implements the 4th version of the OTR protocol.",
      "This version provides better deniability properties by the use of a "
      "deniable authenticated key exchange (DAKE), and better forward secrecy "
      "through the use of the double ratchet algorithm.");

  return text;
}

static gchar *get_text_properties() {
  gchar *text;

  text = g_strdup_printf(
      "<span weight=\"bold\" "
      "size=\"larger\">%s</span>\n\n%s\n\n<b>%s</b>\n\n<u>%s</u> "
      "%s\n\n<u>%s</u> %s\n\n<u>%s</u> %s\n\n<u>%s</u> %s\n\n<u>%s</u> "
      "%s\n\n<u>%s</u> %s\n\n<u>%s</u> %s\n\n<b>%s</b>\n\n<u>%s</u> "
      "%s\n\n<u>%s</u> %s\n\n<u>%s</u> %s\n\n<i>%s</i> %s\n\n<i>%s</i> "
      "%s\n\n<i>%s</i> %s",
      "OTRv4 Properties",
      "These are the properties that make OTRv4 different to other protocols:",
      "Cryptographic properties ", "Online Deniability:",
      "Users using OTRv4 cannot provide proof of participation to third "
      "parties without making themselves vulnerable to key compromise "
      "impersonation (KCI) attacks, even if they perform arbitrary protocols "
      "with these third parties during the exchange.",
      "Offline Deniability:",
      "Anyone can forge a transcript between any two parties using only their "
      "long-term public keys. Consequently, no transcript provides evidence of "
      "a past key exchange, because it could have been forged.",
      "Forward Secrecy and Post-Compromise Security:",
      "When using OTRv4 if the state of a party is leaked, none of the "
      "previous messages should get compromised (FS) and once the exposure of "
      "the party’s state ends, security is restored after a few communication "
      "rounds (PCS).",
      "End-to-end encryption:",
      "OTRv4 provides end-to-end encryption, which is a system by which "
      "information is sent over a network in such a way that only the "
      "recipient and sender can read it.",
      "Participation deniability:",
      "Given a conversation through OTRv4 and all cryptographic key material "
      "for all but one accused (honest) participant, there is no evidence that "
      "the honest participant was in a conversation with any of the other "
      "participants.",
      "Message deniability:",
      "Given a conversation using OTRv4 and all cryptographic keys, there is "
      "no evidence that a given message was authored by any particular user.",
      "Immediate decryption:",
      "Using OTRv4 implies that parties seamlessly recover if a given message "
      "is permanently lost.",
      "Network properties", "Message-loss resilience:",
      "With OTRv4, if a message is permanently lost by the network, parties "
      "should still be able to communicate.",
      "Support of out-of-order:",
      "OTRv4 support Out-of-Order Resilient. If a message is delayed in "
      "transit, but eventually arrives, its contents are accessible upon "
      "arrival.",
      "Support of different modes:", "OTRv4 define three different modes:",
      "OTRv3-compatible mode:",
      "a mode with backwards compatibility with OTRv3. This mode will know how "
      "to handle plaintext messages, including query messages and whitespace "
      "tags.",
      "OTRv4-standalone mode:",
      "an always encrypted mode. This mode will not know how to handle any "
      "kind of plaintext messages, including query messages and whitespace "
      "tags. It supports both interactive and non-interactive conversations. "
      "It is not backwards compatible with OTRv3.",
      "OTRv4-interactive-only:",
      "an always encrypted mode that provides higher deniability properties "
      "when compared to the previous two modes, as it achieves offline and "
      "online deniability for both participants in a conversation. It only "
      "supports interactive conversations. It is not backwards compatible with "
      "OTRv3. This mode can be used by network models that do not have a "
      "central infrastructure, like Ricochet (keep in mind, though, that if "
      "OTRv4 is used over Ricochet, some online deniability properties will be "
      "lost)");

  return text;
}

static gchar *get_text_cryptographic() {
  gchar *text;

  text = g_strdup_printf(
      "<span weight=\"bold\" "
      "size=\"larger\">%s</span>\n\n%s\n\n%s\n\n%s\n\n%s\n\n%s",
      "OTRv4 Cryptographic Suite",
      "These are the cryptographic algorithms used by OTRv4:",
      "Deniable Authenticated Key Exchange (a way to generate a first shared "
      "secret and to deniably authenticate each other): DAKEZ and XZDH",
      "Verification (a way to verify that you are indeed talking to whom you "
      "think): Fingerprint comparison and the Socialist Millionaire Protocol",
      "Conversation Encryption and Authentication (algorithms used to generate keys to encrypt messages and to authenticate them): The double ratchet algorithm,  XSalsa20, MAC \
Key generation (algorithms used for the key generation): ECDH (Ed448) and DH (dh 3072)",
      "Hash Functions (algorithms used to derive keys): SHAKE-256");

  return text;
}

static gchar *get_text_conversation_status() {
  gchar *text;

  text = g_strdup_printf(
      "<span weight=\"bold\" "
      "size=\"larger\">%s</span>\n\n<b>%s</b>\n%s\n\n<b>%s</b>\n%s\n\n"
      "<b>%s</b>\n%s\n\n<b>%s</b>\n%s",
      "OTRv4 Conversation Privacy Status", "Not private",
      "Alice and Bob are communicating with no cryptographic protection; they "
      "are not using OTRv4 at all. Mallory, who is watching the network, can "
      "read everything they are saying to each other.",
      "Private",
      "Alice and Bob are using OTRv4, and they have authenticated each other. "
      "They are assured that they are actually talking to each other, and not "
      "to an imposter. They are also confident that no one watching the "
      "network can read their messages.",
      "Unverified",
      "Alice and Bob are using OTRv4, but they have not authenticated each "
      "other, which means they do not know for certain who they are talking "
      "to. It is possible that Mallory is impersonating one of them, or "
      "intercepting their conversation and reading everything they say to each "
      "other.",
      "Finished",
      "Alice was talking to Bob using OTRv4, but Bob has decided to stop using "
      "it. In this level, Alice is prevented from accidentally sending a "
      "private message without protection, by preventing her from sending any "
      "further messages to Bob at all. She must explicitly either end her "
      "side of the private conversation, or else start a new one.");

  return text;
}

static void set_label_wrap_size(GtkWidget *label, GtkAllocation *alloc,
                                gpointer data) {
  gtk_widget_set_size_request(label, alloc->width - 2, -1);
}

static GtkWidget *get_tab_content(gchar *label) {

  GtkWidget *dialog_text, *scrolled_window, *viewport;
  GtkAdjustment *horizontal, *vertical;

  dialog_text = gtk_label_new(NULL);
  gtk_misc_set_alignment(GTK_MISC(dialog_text), 0, 0.5);
  gtk_label_set_use_markup(GTK_LABEL(dialog_text), TRUE);
  gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
  gtk_label_set_markup(GTK_LABEL(dialog_text), label);
  gtk_label_set_selectable(GTK_LABEL(dialog_text), FALSE);

  g_signal_connect(G_OBJECT(dialog_text), "size-allocate",
                   G_CALLBACK(set_label_wrap_size), NULL);

  scrolled_window = gtk_scrolled_window_new(NULL, NULL);
  horizontal =
      gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(scrolled_window));
  vertical =
      gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scrolled_window));
  viewport = gtk_viewport_new(horizontal, vertical);

  gtk_container_set_border_width(GTK_CONTAINER(scrolled_window), 5);
  gtk_container_set_border_width(GTK_CONTAINER(viewport), 5);

  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                 GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window),
                                        dialog_text);

  return scrolled_window;
}

static void set_notebook_tab(GtkWidget *notebook, char *tab_title,
                             gchar *tab_content_main) {

  GtkWidget *label_tab, *content_tab;

  label_tab = gtk_label_new(tab_title);

  content_tab = get_tab_content(tab_content_main);

  gtk_widget_set_visible(content_tab, TRUE);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), content_tab, label_tab);
}

static GtkWidget *get_notebook(gint page_num) {
  GtkWidget *notebook;
  gchar *text_main, *text_properties, *text_cryptographic,
      *text_conversation_status;

  notebook = gtk_notebook_new();

  gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), TRUE);

  text_main = get_text_main();
  text_properties = get_text_properties();
  text_cryptographic = get_text_cryptographic();
  text_conversation_status = get_text_conversation_status();

  set_notebook_tab(notebook, _("Main Information"), text_main);
  set_notebook_tab(notebook, _("OTRv4 Properties"), text_properties);
  set_notebook_tab(notebook, _("OTRv4 Cryptographic Suite"),
                   text_cryptographic);
  set_notebook_tab(notebook, _("Conversation Status"),
                   text_conversation_status);

  if (page_num) {
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), page_num);
  }

  g_free(text_main);
  g_free(text_properties);
  g_free(text_cryptographic);
  g_free(text_conversation_status);

  return notebook;
}

static void otr_show_help_dialog(gint page_num) {
  GtkWidget *dialog, *notebook;
  gint select_page_num = page_num;

  dialog = gtk_dialog_new_with_buttons(_("Understanding OTRv4"), NULL, 0, NULL,
                                       GTK_RESPONSE_CLOSE, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 5);
  gtk_window_set_default_size(GTK_WINDOW(dialog), 700, 400);

  notebook = get_notebook(select_page_num);

  gtk_window_set_resizable(GTK_WINDOW(dialog), TRUE);
  gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
  g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(destroy_dialog_cb),
                   NULL);
  gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), notebook);

  gtk_widget_show_all(dialog);
}

static void otr_show_info_ssid() {
  GtkWidget *dialog, *text;
  GtkTextBuffer *buffer;
  gchar *textSSID;

  textSSID = "The secure session ID (SSID) is a 8-byte value. It can be used "
             "by participants in a conversation to verify (over the telephone, "
             "for example, "
             "assuming the participants recognize each others' voices) that "
             "there is no man-in-the-middle "
             "(https://en.wikipedia.org/wiki/Man-in-the-middle_attack) "
             "by having each side read his bold part to the other. In order to "
             "verify it, tell the bold side of the SSID to the person you "
             "are talking to and they should tell you their side.";

  // TextView
  text = gtk_text_view_new();

  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text), GTK_WRAP_WORD);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text), TRUE);
  gtk_text_view_set_pixels_above_lines(GTK_TEXT_VIEW(text), 5);
  gtk_text_view_set_pixels_below_lines(GTK_TEXT_VIEW(text), 5);
  gtk_text_view_set_pixels_inside_wrap(GTK_TEXT_VIEW(text), 5);
  gtk_text_view_set_left_margin(GTK_TEXT_VIEW(text), 10);
  gtk_text_view_set_right_margin(GTK_TEXT_VIEW(text), 10);

  // Buffer
  buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text));
  gtk_text_buffer_set_text(buffer, textSSID, -1);

  dialog = gtk_dialog_new_with_buttons(_("SSID"), NULL, 0, NULL,
                                       GTK_RESPONSE_CLOSE, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 5);
  gtk_widget_set_size_request(dialog, 350, 200);
  gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
  gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
  g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(destroy_dialog_cb),
                   NULL);
  gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), text);

  gtk_widget_show_all(dialog);
}

static void menu_understanding_otrv4(GtkWidget *widget, gpointer data) {
  gint default_page = 0;
  otr_show_help_dialog(default_page);
}

static GtkWidget * otr_about_logo(){

	GError *error = NULL;
	GtkWidget *image = NULL;

	char *logo_base64 = "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";

	gsize logo_length = sizeof( logo_base64 );

	guchar *logo_decoded = g_base64_decode( logo_base64 , &logo_length );

	GInputStream *logo_stream = g_memory_input_stream_new_from_data( logo_decoded , logo_length , NULL );

	GdkPixbuf *pix = gdk_pixbuf_new_from_stream( logo_stream , NULL , &error );

	image = gtk_image_new_from_pixbuf( pix );

	return image;
}

static gchar *otr_about_text_credits(){

	 gchar *text;

	 text = g_strdup_printf("%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
							"Team OTR:",
							"- Ian Goldberg",
							"- Nik Unger",
							"- Mike Hamburg",
							"- Sofia Celi",
							"- Ola Bini",
							"- Reinaldo de Souza Jr",
							"- Rosalie Tolentino",
							"- Jurre van Bergen",
							"- Dave Goulet",
							"- Iván Pazmiño",
							"- Giovane Liberato",
							"- Fan Jiang",
							"- Nikita Borisov",
							"- Katrina Hanna",
							"- Rob Smits",
							"- Chris Alexander",
							"- Willy Lew",
							"- Lisa Du",
							"- Md. Muhaimeen Ashraf",
							"- Pedro Palau",
							"- Mauro Velasco",
							"- Cristina Salcedo");

	 return text;
}

static GtkWidget * otr_about_info(){

	GtkWidget *box, *credits;

	box = gtk_hbox_new( FALSE , 0 );
	credits = gtk_label_new( otr_about_text_credits() );

	gtk_box_pack_start (GTK_BOX(box), otr_about_logo(), TRUE, TRUE, 3);
	gtk_box_pack_start (GTK_BOX(box), credits, TRUE, TRUE, 3);


	return box;
}

static void otr_show_about_dialog(gint page_num) {

  GtkWidget *dialog;

  dialog = gtk_dialog_new_with_buttons(_("About"), NULL, 0, NULL,
                                       GTK_RESPONSE_CLOSE, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 5);
  gtk_window_set_default_size(GTK_WINDOW(dialog), 780 , 440);

  gtk_window_set_resizable(GTK_WINDOW(dialog), TRUE);
  gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
  g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(destroy_dialog_cb),
                   NULL);

  gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), otr_about_info());

  gtk_widget_show_all(dialog);
}


static void show_menu_about_otrv4(GtkWidget *widget, gpointer data) {
  gint default_page = 0;
  otr_show_about_dialog(default_page);
}

static void menu_end_private_conversation(GtkWidget *widget, gpointer data) {
  otrng_ui_disconnect_connection(data);
  otrng_plugin_conversation_free(data);
}

static void dialog_resensitize(PurpleConversation *conv);

/* If the OTR button is right-clicked, show the context menu. */
static gboolean button_pressed(GtkWidget *w, GdkEventButton *event,
                               gpointer data) {
  PurpleConversation *conv = data;

  /* Any button will do */
  if (event->type == GDK_BUTTON_PRESS) {
    GtkWidget *menu = purple_conversation_get_data(conv, "otr-menu");
    if (menu) {
      gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 3, event->time);
      return TRUE;
    }
  }

  return FALSE;
}

static void otrng_gtk_dialog_new_purple_conv(PurpleConversation *conv);

static void otr_refresh_otr_buttons(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  GList *list_iter = gtkconv->convs;
  PurpleConversation *current_conv;
  GtkWidget *button;

  for (; list_iter; list_iter = list_iter->next) {

    current_conv = list_iter->data;
    button = purple_conversation_get_data(current_conv, "otr-button");

    if (button) {
      if (current_conv == gtkconv->active_conv) {
        gtk_widget_show(button);
      } else {
        gtk_widget_hide(button);
      }
    }
  }
}

/* Menu has been destroyed -- let's remove it from the menu_list
 * so that it won't be destroyed again. */
static void otr_menu_destroy(GtkWidget *widget, gpointer pdata) {
  PidginWindow *win = (PidginWindow *)pdata;
  GtkWidget *top_menu = widget;

  GList *menu_list = g_hash_table_lookup(otr_win_menus, win);
  menu_list = g_list_remove(menu_list, top_menu);
  g_hash_table_replace(otr_win_menus, win, menu_list);
}

static void otr_clear_win_menu_list(PidginWindow *win) {
  GList *head = g_hash_table_lookup(otr_win_menus, win); /* menu_list */
  GList *old_head = 0;

  while (head) {
    old_head = head;
    gtk_object_destroy(GTK_OBJECT(head->data));
    head = g_hash_table_lookup(otr_win_menus, win);

    if (head && head == old_head) {
      /* The head was not removed by the "destroyed" callback
         Something is wrong */
      break;
    }
  }

  g_hash_table_replace(otr_win_menus, win, head);
}

static void otr_destroy_top_menu_objects(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  PidginWindow *win = pidgin_conv_get_window(gtkconv);

  otr_clear_win_menu_list(win);
}

static int otr_get_menu_insert_pos(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  PidginWindow *win = pidgin_conv_get_window(gtkconv);
  GtkWidget *menu_bar = win->menu.menubar;

  GList *list_iter = gtk_container_get_children(GTK_CONTAINER(menu_bar));
  GList *head = list_iter;

  int pos = 0;
  while (list_iter) {
    pos++;
    list_iter = list_iter->next;
  }

  if (pos != 0) {
    pos--;
  }

  g_list_free(head);

  return pos;
}

static void otr_set_menu_labels(PurpleConversation *conv, GtkWidget *query,
                                GtkWidget *end, GtkWidget *smp) {
  int insecure = 0;
  int authen = 0;
  int finished = 0;

  if (!conv) {
    return;
  }

  insecure = purple_conversation_get_data(conv, "otr-private") ? 0 : 1;
  authen = purple_conversation_get_data(conv, "otr-authenticated") ? 1 : 0;
  finished = purple_conversation_get_data(conv, "otr-finished") ? 1 : 0;

  GtkWidget *label = gtk_bin_get_child(GTK_BIN(query));

  gtk_label_set_markup_with_mnemonic(
      GTK_LABEL(label), insecure ? _("Start _private conversation")
                                 : _("Refresh _private conversation"));

  label = gtk_bin_get_child(GTK_BIN(smp));

  gtk_label_set_markup_with_mnemonic(
      GTK_LABEL(label), (!insecure && authen) ? _("Re_authenticate buddy")
                                              : _("_Authenticate buddy"));

  gtk_widget_set_sensitive(GTK_WIDGET(end), !(insecure || finished));
  gtk_widget_set_sensitive(GTK_WIDGET(smp), !insecure);
}

static void force_deselect(GtkItem *item, gpointer data) {
  gtk_item_deselect(item);
}

static void otr_build_status_submenu(PidginWindow *win,
                                     const ConvOrContext *convctx,
                                     GtkWidget *menu, TrustLevel level) {
  char *status = "";
  GtkWidget *image;
  GtkWidget *levelimage;
  GtkWidget *buddy_name;
  GtkWidget *buddy_status;
  GtkWidget *menusep, *menusep2;
  GdkPixbuf *pixbuf;
  GtkWidget *understanding_otrv4;
  GtkWidget *about;

  gchar *text = NULL;

  PurpleConversation *conv;

  if (convctx->convctx_type == convctx_conv) {
    conv = convctx->conv;
  } else if (convctx->convctx_type == convctx_ctx) {
    conv = otrng_plugin_context_to_conv(convctx->context, 0);
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

  gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(buddy_name), image);

  switch (level) {
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

  gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(buddy_status), levelimage);

  menusep = gtk_separator_menu_item_new();
  menusep2 = gtk_separator_menu_item_new();
  understanding_otrv4 =
      gtk_image_menu_item_new_with_mnemonic(_("_Understanding OTRv4"));
  gtk_image_menu_item_set_image(
      GTK_IMAGE_MENU_ITEM(understanding_otrv4),
      gtk_image_new_from_stock(
          GTK_STOCK_HELP,
          gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_EXTRA_SMALL)));

  about = gtk_image_menu_item_new_with_mnemonic(_("_About"));
  gtk_image_menu_item_set_image(
        GTK_IMAGE_MENU_ITEM(about),
        gtk_image_new_from_stock(
            GTK_STOCK_HELP,
            gtk_icon_size_from_name(PIDGIN_ICON_SIZE_TANGO_EXTRA_SMALL)));

  gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_name);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_status);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep2);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), understanding_otrv4);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), about);

  gtk_widget_show(menusep);
  gtk_widget_show_all(buddy_name);
  gtk_widget_show_all(buddy_status);
  gtk_widget_show(menusep2);
  gtk_widget_show_all(understanding_otrv4);
  gtk_widget_show_all(about);

  gtk_signal_connect(GTK_OBJECT(buddy_name), "select",
                     GTK_SIGNAL_FUNC(force_deselect), NULL);
  gtk_signal_connect(GTK_OBJECT(buddy_status), "select",
                     GTK_SIGNAL_FUNC(force_deselect), NULL);
  gtk_signal_connect(GTK_OBJECT(understanding_otrv4), "activate",
                     GTK_SIGNAL_FUNC(menu_understanding_otrv4), conv);
  gtk_signal_connect(GTK_OBJECT(about), "activate",
                     GTK_SIGNAL_FUNC(show_menu_about_otrv4), conv);
}

static void build_otr_menu(PurpleConversation *conv, GtkWidget *menu,
                           TrustLevel level) {
  if (!conv) {
    return;
  }

  GtkWidget *buddymenuquery =
      gtk_menu_item_new_with_mnemonic(_("Start _private conversation"));
  GtkWidget *buddymenuend =
      gtk_menu_item_new_with_mnemonic(_("_End private conversation"));
  GtkWidget *buddymenusmp =
      gtk_menu_item_new_with_mnemonic(_("_Authenticate buddy"));

  otr_set_menu_labels(conv, buddymenuquery, buddymenuend, buddymenusmp);

  /* Empty out the menu */
  gtk_container_foreach(GTK_CONTAINER(menu), destroy_menuitem, NULL);

  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenuquery);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenuend);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddymenusmp);

  gtk_widget_show(buddymenuquery);
  gtk_widget_show(buddymenuend);
  gtk_widget_show(buddymenusmp);

  gtk_signal_connect(GTK_OBJECT(buddymenuquery), "activate",
                     GTK_SIGNAL_FUNC(otrng_gtk_dialog_clicked_connect), conv);
  gtk_signal_connect(GTK_OBJECT(buddymenuend), "activate",
                     GTK_SIGNAL_FUNC(menu_end_private_conversation),
                     purple_conversation_to_plugin_conversation(conv));
  gtk_signal_connect(GTK_OBJECT(buddymenusmp), "activate",
                     GTK_SIGNAL_FUNC(socialist_millionaires), (gpointer)conv);
}

static void otr_add_top_otr_menu(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  PidginWindow *win = pidgin_conv_get_window(gtkconv);
  GtkWidget *menu_bar = win->menu.menubar;

  GList *menu_list = g_hash_table_lookup(otr_win_menus, win);

  GtkWidget *topmenu;
  GtkWidget *topmenuitem;

  TrustLevel level = TRUST_NOT_PRIVATE;
  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  if (plugin_conv) {
    level = otrng_plugin_conversation_to_trust(plugin_conv);
  }
  otrng_plugin_conversation_free(plugin_conv);

  ConvOrContext *convctx;
  GHashTable *conv_or_ctx_map =
      purple_conversation_get_data(conv, "otr-convorctx");

  int pos = otr_get_menu_insert_pos(conv);

  if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) {
    return;
  }

  topmenuitem = gtk_menu_item_new_with_label("OTR");
  topmenu = gtk_menu_new();

  convctx = g_hash_table_lookup(conv_or_ctx_map, conv);

  if (!convctx) {
    convctx = malloc(sizeof(ConvOrContext));
    g_hash_table_insert(conv_or_ctx_map, conv, (gpointer)convctx);
  }

  convctx->convctx_type = convctx_conv;
  convctx->conv = conv;
  build_otr_menu(conv, topmenu, level);
  otr_build_status_submenu(win, convctx, topmenu, level);

  gtk_menu_item_set_submenu(GTK_MENU_ITEM(topmenuitem), topmenu);

  gtk_widget_show(topmenuitem);
  gtk_widget_show(topmenu);

  gtk_menu_shell_insert(GTK_MENU_SHELL(menu_bar), topmenuitem, pos++);

  g_signal_connect(G_OBJECT(topmenuitem), "destroy",
                   G_CALLBACK(otr_menu_destroy), win);

  menu_list = g_list_append(menu_list, topmenuitem);

  g_hash_table_replace(otr_win_menus, win, menu_list);
}

/* If the conversation switches on us */
static void conversation_switched(PurpleConversation *conv, void *data) {
  if (conv == NULL) {
    return;
  }

  otrng_gtk_dialog_new_purple_conv(conv);
}

/* If the conversation gets destroyed on us, clean up the data we stored
 * pointing to it. */
static void conversation_destroyed(PurpleConversation *conv, void *data) {
  GtkWidget *menu = (GtkWidget *)purple_conversation_get_data(conv, "otr-menu");
  PidginConversation *gtkconv;
  PidginWindow *win;
  GHashTable *conv_or_ctx_map;
  GHashTable *conv_to_idx_map;
  gint *max_instance_idx;
  gboolean *is_conv_multi_instance;
  gboolean *have_warned_instances;
  otrl_instag_t *last_received_instance;

  if (menu) {
    gtk_object_destroy(GTK_OBJECT(menu));
  }

  conv_or_ctx_map = purple_conversation_get_data(conv, "otr-convorctx");
  g_hash_table_destroy(conv_or_ctx_map);

  conv_to_idx_map = purple_conversation_get_data(conv, "otr-conv_to_idx");
  g_hash_table_destroy(conv_to_idx_map);

  max_instance_idx = purple_conversation_get_data(conv, "otr-max_idx");
  if (max_instance_idx) {
    g_free(max_instance_idx);
  }

  is_conv_multi_instance =
      purple_conversation_get_data(conv, "otr-conv_multi_instances");
  if (is_conv_multi_instance) {
    g_free(is_conv_multi_instance);
  }

  have_warned_instances =
      purple_conversation_get_data(conv, "otr-warned_instances");
  if (have_warned_instances) {
    g_free(have_warned_instances);
  }

  last_received_instance =
      purple_conversation_get_data(conv, "otr-last_received_ctx");
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

  otrng_gtk_dialog_free_smp_data(conv);

  gtkconv = PIDGIN_CONVERSATION(conv);

  /* Only delete the OTR menus if we're the active conversation */
  if (gtkconv != pidgin_conv_window_get_active_gtkconv(gtkconv->win)) {
    return;
  }

  win = pidgin_conv_get_window(gtkconv);

  otr_clear_win_menu_list(win);

  g_hash_table_remove(otr_win_menus, win);
}

/* Set up the per-conversation information display */
static void otrng_gtk_dialog_new_purple_conv(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
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

  GHashTable *conv_or_ctx_map;
  GHashTable *ctx_to_idx_map;

  gint *max_instance_idx;
  gboolean *is_conv_multi_instance;
  gboolean *have_warned_instances;
  otrl_instag_t *last_received_instance;

  /* Do nothing if this isn't an IM conversation */
  if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) {
    return;
  }

  /* Get the prefs */
  account = purple_conversation_get_account(conv);
  name = purple_conversation_get_name(conv);
  otrng_ui_get_prefs(&prefs, account, name);

  /* OTR is disabled for this buddy */
  if (prefs.policy == OTRL_POLICY_NEVER) {
    otr_destroy_top_menu_objects(conv);
    return;
  }

  bbox = gtkconv->toolbar;

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  TrustLevel level = otrng_plugin_conversation_to_trust(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);

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
    dialog_update_label_conv(conv, level);
    return;
  }

  conv_or_ctx_map =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free);
  purple_conversation_set_data(conv, "otr-convorctx", conv_or_ctx_map);

  ctx_to_idx_map =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
  purple_conversation_set_data(conv, "otr-conv_to_idx", ctx_to_idx_map);

  max_instance_idx = g_malloc(sizeof(gint));
  *max_instance_idx = 0;
  purple_conversation_set_data(conv, "otr-max_idx", (gpointer)max_instance_idx);

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
  g_hash_table_replace(conv_or_ctx_map, conv, convctx);
  build_otr_menu(conv, menu, TRUST_NOT_PRIVATE);
  otr_build_status_submenu(pidgin_conv_get_window(gtkconv), convctx, menu,
                           TRUST_NOT_PRIVATE);

  purple_conversation_set_data(conv, "otr-label", label);
  purple_conversation_set_data(conv, "otr-button", button);
  purple_conversation_set_data(conv, "otr-icon", icon);
  purple_conversation_set_data(conv, "otr-menu", menu);
  g_signal_connect(G_OBJECT(button), "button-press-event",
                   G_CALLBACK(button_pressed), conv);

  dialog_update_label_conv(conv, level);
  dialog_resensitize(conv);

  /* Finally, add the state for the socialist millionaires dialogs */
  otrng_gtk_dialog_add_smp_data(conv);
}

/* Set up the per-conversation information display */
static void otrng_gtk_dialog_new_conv(PurpleConversation *conv) {
  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
  conversation_switched(gtkconv->active_conv, NULL);
}

/* Remove the per-conversation information display */
static void otrng_gtk_dialog_remove_conv(PurpleConversation *conv) {
  GtkWidget *button;

  /* Do nothing if this isn't an IM conversation */
  if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) {
    return;
  }

  button = purple_conversation_get_data(conv, "otr-button");
  if (button) {
    gtk_object_destroy(GTK_OBJECT(button));
  }

  conversation_destroyed(conv, NULL);
}

/* Set the OTR button to "sensitive" or "insensitive" as appropriate. */
static void dialog_resensitize(PurpleConversation *conv) {
  PurpleAccount *account;
  PurpleConnection *connection;
  GtkWidget *button;
  const char *name;
  OtrgUiPrefs prefs;

  /* Do nothing if this isn't an IM conversation */
  if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) {
    return;
  }

  account = purple_conversation_get_account(conv);
  name = purple_conversation_get_name(conv);
  otrng_ui_get_prefs(&prefs, account, name);

  if (prefs.policy == OTRL_POLICY_NEVER) {
    otrng_gtk_dialog_remove_conv(conv);
  } else {
    otrng_gtk_dialog_new_conv(conv);
  }
  button = purple_conversation_get_data(conv, "otr-button");
  if (!button) {
    return;
  }
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
static void otrng_gtk_dialog_resensitize_all(void) {
  purple_conversation_foreach(dialog_resensitize);
}

static void foreach_free_lists(void *key, void *value, void *data) {
  PidginWindow *win = (PidginWindow *)key;

  otr_clear_win_menu_list(win);
}

static char *conversation_timestamp(PurpleConversation *conv, time_t mtime,
                                    gboolean show_date) {

  PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);

  TrustLevel current_level = TRUST_NOT_PRIVATE;
  TrustLevel *previous_level = NULL;

  int id = 0;

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  current_level = otrng_plugin_conversation_to_trust(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);

  previous_level = (TrustLevel *)g_hash_table_lookup(otr_win_status, gtkconv);

  if (!previous_level) {
    return NULL;
  }

  if (*previous_level == current_level) {
    return NULL;
  }

  switch (current_level) {
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

  if (id > 0) {
    char *msg = g_strdup_printf("<IMG ID=\"%d\"> ", id);
    gtk_imhtml_append_text_with_images((GtkIMHtml *)gtkconv->imhtml, msg, 0,
                                       NULL);
    g_free(msg);
  }

  return NULL;
}

/* If the user has selected a meta instance, an incoming message may trigger
 * an instance change... we need to update the GUI appropriately */
static gboolean check_incoming_instance_change(PurpleAccount *account,
                                               char *sender, char *message,
                                               PurpleConversation *conv,
                                               PurpleMessageFlags flags) {
  // TODO: We dont have the meta instance tag in OTR4
  // Double check this function
  otrl_instag_t *last_received_instance;
  otrl_instag_t selected_instance;
  gboolean have_received = FALSE;
  ConnContext *received_context = NULL;

  if (!conv || !conv->data) {
    return 0;
  }

  selected_instance = otrng_plugin_conv_to_selected_instag(conv, 0);

  last_received_instance =
      g_hash_table_lookup(conv->data, "otr-last_received_ctx");

  if (!last_received_instance) {
    return 0; /* OTR disabled for this buddy */
  }

  if (*last_received_instance == OTRL_INSTAG_MASTER ||
      *last_received_instance >= OTRL_MIN_VALID_INSTAG) {
    have_received = TRUE;
  }

  received_context = (ConnContext *)otrng_plugin_conv_to_context(
      conv, (otrl_instag_t)OTRL_INSTAG_RECENT_RECEIVED, 0);

  if (!received_context) {
    return 0;
  }

  if (have_received &&
      *last_received_instance != received_context->their_instance &&
      selected_instance != OTRL_INSTAG_MASTER &&
      selected_instance < OTRL_MIN_VALID_INSTAG) {

    otrng_plugin_conversation *plugin_conv =
        purple_conversation_to_plugin_conversation(conv);
    dialog_update_label_conv(conv,
                             otrng_plugin_conversation_to_trust(plugin_conv));
    otrng_plugin_conversation_free(plugin_conv);
  }

  *last_received_instance = received_context->their_instance;

  return 0;
}

static void connection_signing_off_cb(PurpleConnection *conn) {
  PurpleAccount *account;
  otrng_client_s *client = NULL;
  list_element_s *el = NULL;
  otrng_conversation_s *otr_conv = NULL;
  otrng_plugin_conversation *otr_plugin_conv = NULL;

  account = purple_connection_get_account(conn);
  if (!account) {
    return;
  }

  client = purple_account_to_otrng_client(account);
  if (!client) {
    return;
  }

  for (el = client->conversations; el; el = el->next) {
    otr_conv = el->data;
    if (!otr_conv) {
      continue;
    }

    if (!otrng_conversation_is_encrypted(otr_conv)) {
      continue;
    }

    otr_plugin_conv =
        client_conversation_to_plugin_conversation(otr_conv->conn);

    if (otr_plugin_conv) {
      otrng_ui_disconnect_connection(otr_plugin_conv);
      otrng_plugin_conversation_free(otr_plugin_conv);
    }
  }
}

static void unref_img_by_id(int *id) {
  if (id && *id > 0) {
    purple_imgstore_unref_by_id(*id);
    *id = -1;
  }
}

static void dialog_quitting(void) {
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
static void otrng_gtk_dialog_init(void) {
  otr_win_menus = g_hash_table_new(g_direct_hash, g_direct_equal);
  otr_win_status =
      g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free);

  img_id_not_private = purple_imgstore_add_with_id(
      g_memdup(not_private_png, sizeof(not_private_png)),
      sizeof(not_private_png), "");

  img_id_unverified = purple_imgstore_add_with_id(
      g_memdup(unverified_png, sizeof(unverified_png)), sizeof(unverified_png),
      "");

  img_id_private = purple_imgstore_add_with_id(
      g_memdup(private_png, sizeof(private_png)), sizeof(private_png), "");

  img_id_finished = purple_imgstore_add_with_id(
      g_memdup(finished_png, sizeof(finished_png)), sizeof(finished_png), "");

  purple_signal_connect(pidgin_conversations_get_handle(),
                        "conversation-switched", otrng_plugin_handle,
                        PURPLE_CALLBACK(conversation_switched), NULL);

  purple_signal_connect(purple_conversations_get_handle(),
                        "deleting-conversation", otrng_plugin_handle,
                        PURPLE_CALLBACK(conversation_destroyed), NULL);

  purple_signal_connect(pidgin_conversations_get_handle(),
                        "conversation-timestamp", otrng_plugin_handle,
                        PURPLE_CALLBACK(conversation_timestamp), NULL);

  purple_signal_connect(purple_conversations_get_handle(), "received-im-msg",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(check_incoming_instance_change), NULL);

  purple_signal_connect(purple_get_core(), "quitting", otrng_plugin_handle,
                        PURPLE_CALLBACK(dialog_quitting), NULL);

  purple_signal_connect(purple_connections_get_handle(), "signing-off",
                        otrng_plugin_handle,
                        PURPLE_CALLBACK(connection_signing_off_cb), NULL);

  otrng_utils_init();
}

/* Deinitialize the OTR dialog subsystem */
static void otrng_gtk_dialog_cleanup(void) {
  purple_signal_disconnect(purple_get_core(), "quitting", otrng_plugin_handle,
                           PURPLE_CALLBACK(dialog_quitting));

  purple_signal_disconnect(pidgin_conversations_get_handle(),
                           "conversation-switched", otrng_plugin_handle,
                           PURPLE_CALLBACK(conversation_switched));

  purple_signal_disconnect(pidgin_conversations_get_handle(),
                           "conversation-timestamp", otrng_plugin_handle,
                           PURPLE_CALLBACK(conversation_timestamp));

  purple_signal_disconnect(purple_conversations_get_handle(),
                           "deleting-conversation", otrng_plugin_handle,
                           PURPLE_CALLBACK(conversation_destroyed));

  purple_signal_disconnect(purple_conversations_get_handle(), "received-im-msg",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(check_incoming_instance_change));

  purple_signal_disconnect(purple_connections_get_handle(), "signing-off",
                           otrng_plugin_handle,
                           PURPLE_CALLBACK(connection_signing_off_cb));

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

  otrng_utils_uninit();
}

static const OtrgDialogUiOps gtk_dialog_ui_ops = {
    otrng_gtk_dialog_init,
    otrng_gtk_dialog_cleanup,
    otrng_gtk_dialog_notify_message,
    otrng_gtk_dialog_display_otr_message,
    otrng_gtk_dialog_private_key_wait_start,
    otrng_gtk_dialog_private_key_wait_done,
    otrng_gtk_dialog_unknown_fingerprint,
    otrng_gtk_dialog_verify_fingerprint,
    otrng_gtk_dialog_socialist_millionaires,
    otrng_gtk_dialog_update_smp,
    otrng_gtk_dialog_connected_real,
    otrng_gtk_dialog_disconnected_real,
    otrng_gtk_dialog_stillconnected,
    otrng_gtk_dialog_finished,
    otrng_gtk_dialog_resensitize_all,
    otrng_gtk_dialog_new_conv,
    otrng_gtk_dialog_remove_conv};

/* Get the GTK dialog UI ops */
const OtrgDialogUiOps *otrng_gtk_dialog_get_ui_ops(void) {
  return &gtk_dialog_ui_ops;
}

static void otr_show_status_dialog() {
  gint status_page = 3;
  otr_show_help_dialog(status_page);
}

static gboolean otrng_open_status_help_dialog(GtkIMHtml *imhtml,
                                              GtkIMHtmlLink *link) {
  const char *url;
  const char *status;

  url = gtk_imhtml_link_get_url(link);
  if (!url || strlen(url) < sizeof("viewstatus:"))
    return FALSE;

  // TODO: check if the status value is valid
  status = url + sizeof("viewstatus:") - 1;

  if (status) {
    otr_show_status_dialog();
    return TRUE;
  }

  return FALSE;
}

static gboolean otrng_open_info_ssid(GtkIMHtml *imhtml, GtkIMHtmlLink *link) {

  otr_show_info_ssid();

  return TRUE;
}

static gboolean otrng_status_context_menu(GtkIMHtml *imhtml,
                                          GtkIMHtmlLink *link,
                                          GtkWidget *menu) {
  // TODO: Check if necessary to create a context menu here
  return TRUE;
}

void otrng_utils_init(void) {
  gtk_imhtml_class_register_protocol(
      "viewstatus:", otrng_open_status_help_dialog, otrng_status_context_menu);
  gtk_imhtml_class_register_protocol("ssid", otrng_open_info_ssid, NULL);
}

void otrng_utils_uninit(void) {
  gtk_imhtml_class_register_protocol("viewstatus:", NULL, NULL);
  gtk_imhtml_class_register_protocol("ssid", NULL, NULL);
}
