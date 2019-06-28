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
    const otrng_known_fingerprint_s *other_fprint, const char *protocol,
    const char *account) {
  char our_human_fprint[OTRNG_FPRINT_HUMAN_LEN];
  char other_human_fprint[OTRNG_FPRINT_HUMAN_LEN];
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

  otrng_fingerprint_hash_to_human(other_human_fprint, other_fprint->fp);

  label_text = g_strdup_printf(_("Fingerprint for you, %s (%s):\n%s\n\n"
                                 "Purported fingerprint for %s:\n%s\n"),
                               account, proto_name, our_human_fprint,
                               other_fprint->username, other_human_fprint);

  return label_text;
}

static char *
create_verify_fingerprint_label(const otrng_plugin_fingerprint_s *other_fprint,
                                const char *protocol, const char *account) {
  if (other_fprint->version == 3) {
    return create_verify_fingerprint_label_v3(other_fprint->v3, protocol,
                                              account);
  }
  return create_verify_fingerprint_label_v4(other_fprint->v4, protocol,
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
  TrustLevel *previous_level = TRUST_NOT_PRIVATE;

  char *buf;
  char *status = "";

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  current_level = otrng_plugin_conversation_to_trust(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);

  previous_level = (TrustLevel *) g_hash_table_lookup(otr_win_status, gtkconv);

  // Not show the message for an unchanged status
  if (previous_level && *previous_level == current_level) {
    return;
  }

  buf = _("The privacy status of the current conversation is: "
          "%s");

  switch (current_level) {
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

  buf = g_strdup_printf(buf, status);

  /* Write a new message indicating the level change. The timestamp image will
   * be appended as the message timestamp signal is caught, which will also
   * update the privacy level for this gtkconv */
  purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));

  if (conv == gtkconv->active_conv) {
    /* 'free' is handled by the hashtable */
    TrustLevel *current_level_ptr = malloc(sizeof(TrustLevel));
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

static GtkWidget *get_tab_content(gchar *label) {

  GtkWidget *dialog_text, *scrolled_window, *viewport;
  GtkAdjustment *horizontal, *vertical;

  dialog_text = gtk_label_new(NULL);
  gtk_label_set_use_markup(GTK_LABEL(dialog_text), TRUE);
  gtk_label_set_line_wrap(GTK_LABEL(dialog_text), TRUE);
  gtk_label_set_markup(GTK_LABEL(dialog_text), label);
  gtk_label_set_selectable(GTK_LABEL(dialog_text), FALSE);

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

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), content_tab, label_tab);
}

static GtkWidget *get_notebook() {

  GtkWidget *notebook;

  gchar *text_main, *text_properties, *text_cryptographic;

  notebook = gtk_notebook_new();

  text_main = get_text_main();
  text_properties = get_text_properties();
  text_cryptographic = get_text_cryptographic();

  set_notebook_tab(notebook, _("Main Information"), text_main);
  set_notebook_tab(notebook, _("OTRv4 Properties"), text_properties);
  set_notebook_tab(notebook, _("OTRv4 Cryptographic Suite"),
                   text_cryptographic);

  g_free(text_main);
  g_free(text_properties);
  g_free(text_cryptographic);

  return notebook;
}

static void menu_understanding_otrv4(GtkWidget *widget, gpointer data) {
  GtkWidget *dialog, *notebook;

  dialog = gtk_dialog_new_with_buttons(_("Understanding OTRv4"), NULL, 0, NULL,
                                       GTK_RESPONSE_CLOSE, NULL);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
  gtk_container_set_border_width(GTK_CONTAINER(dialog), 5);
  gtk_widget_set_size_request(dialog, 550, 400);

  notebook = get_notebook();

  gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
  gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
  g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(destroy_dialog_cb),
                   NULL);
  gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), notebook);

  gtk_widget_show_all(dialog);
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

  gtk_widget_set_sensitive(GTK_WIDGET(end), !insecure || finished);
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

  gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_name);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), buddy_status);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep2);
  gtk_menu_shell_append(GTK_MENU_SHELL(menu), understanding_otrv4);

  gtk_widget_show(menusep);
  gtk_widget_show_all(buddy_name);
  gtk_widget_show_all(buddy_status);
  gtk_widget_show(menusep2);
  gtk_widget_show_all(understanding_otrv4);

  gtk_signal_connect(GTK_OBJECT(buddy_name), "select",
                     GTK_SIGNAL_FUNC(force_deselect), NULL);
  gtk_signal_connect(GTK_OBJECT(buddy_status), "select",
                     GTK_SIGNAL_FUNC(force_deselect), NULL);
  gtk_signal_connect(GTK_OBJECT(understanding_otrv4), "activate",
                     GTK_SIGNAL_FUNC(menu_understanding_otrv4), conv);
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
  TrustLevel *previous_level = TRUST_NOT_PRIVATE;

  int id = 0;

  otrng_plugin_conversation *plugin_conv =
      purple_conversation_to_plugin_conversation(conv);
  current_level = otrng_plugin_conversation_to_trust(plugin_conv);
  otrng_plugin_conversation_free(plugin_conv);

  previous_level = (TrustLevel *) g_hash_table_lookup(otr_win_status, gtkconv);

  if ((previous_level && *previous_level == current_level) || !previous_level) {
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
