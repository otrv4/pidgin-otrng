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

#include "prekey-discovery-jabber.h"

#include "signal.h"

#include <stdio.h>
#include <string.h>

static GHashTable *iq_callbacks = NULL;
static gboolean iq_listening = FALSE;

static char *generate_next_id() {
  static guint32 index = 0;

  if (index == 0) {
    do {
      index = g_random_int();
    } while (index == 0);
  }

  return g_strdup_printf("otrngprekey%x", index++);
}

static unsigned char *hex_to_bytes(const char *hex, size_t len) {
  size_t count;
  char *pos = (char *)hex;
  unsigned char *result = malloc(len / 2);
  for (count = 0; count < len / 2; count++) {
    sscanf(pos, "%2hhx", &result[count]);
    pos += 2;
  }
  return result;
}

static void
report_found_prekey_server(otrng_plugin_prekey_discovery_status *iq_status,
                           const char *jid, const char *fingerprint) {
  unsigned char *bytefingerprint =
      hex_to_bytes(fingerprint, FINGERPRINT_LENGTH * 2);

  otrng_plugin_prekey_server *res = malloc(sizeof(otrng_plugin_prekey_server));
  res->identity = g_strdup(jid);
  memcpy(res->fingerprint, bytefingerprint, FINGERPRINT_LENGTH);

  iq_status->result_cb(res, iq_status->context);

  free(bytefingerprint);
}

static void receive_prekey_connection_information(PurpleConnection *pc,
                                                  const char *type,
                                                  const char *id,
                                                  const char *from, xmlnode *iq,
                                                  gpointer data) {
  xmlnode *query;

  if (purple_strequal(type, "result") &&
      (query = xmlnode_get_child(iq, "query"))) {
    xmlnode *item;
    for (item = xmlnode_get_child(query, "item"); item;
         item = xmlnode_get_next_twin(item)) {
      const char *jid = xmlnode_get_attrib(item, "jid");
      const char *node = xmlnode_get_attrib(item, "node");
      const char *fingerprint = xmlnode_get_attrib(item, "name");

      if (jid != NULL && purple_strequal(jid, from) && node != NULL &&
          purple_strequal(node, "fingerprint") && fingerprint != NULL &&
          strlen(fingerprint) == 112) {
        report_found_prekey_server(data, jid, fingerprint);
      }
    }
  }
}

static void send_iq(PurpleConnection *pc, const char *to, const char *namespace,
                    otrng_plugin_prekey_discovery_status *handle) {
  xmlnode *iq, *query;
  char *id = generate_next_id();
  iq = xmlnode_new("iq");
  xmlnode_set_attrib(iq, "type", "get");
  xmlnode_set_attrib(iq, "to", to);
  xmlnode_set_attrib(iq, "id", id);

  query = xmlnode_new_child(iq, "query");
  xmlnode_set_namespace(query, namespace);

  g_hash_table_insert(iq_callbacks, id, handle);

  PurplePlugin *prpl = purple_plugins_find_with_id("prpl-jabber");
  purple_signal_emit(prpl, "jabber-sending-xmlnode", pc, &iq);

  if (iq != NULL) {
    xmlnode_free(iq);
  }
}

static void find_connection_information_for(
    PurpleConnection *pc, const char *jid,
    otrng_plugin_prekey_discovery_status *iq_status) {
  otrng_plugin_prekey_discovery_status *new_iq_handle =
      malloc(sizeof(otrng_plugin_prekey_discovery_status));
  new_iq_handle->next = receive_prekey_connection_information;
  new_iq_handle->result_cb = iq_status->result_cb;
  new_iq_handle->context = iq_status->context;

  send_iq(pc, jid, NS_DISCO_ITEMS, new_iq_handle);
}

static void receive_server_info(PurpleConnection *pc, const char *type,
                                const char *id, const char *from, xmlnode *iq,
                                gpointer data) {
  const char *idcat, *idtype;
  xmlnode *query;

  if (purple_strequal(type, "result") &&
      (query = xmlnode_get_child(iq, "query"))) {
    xmlnode *identity = xmlnode_get_child(query, "identity");
    if (identity) {
      idcat = xmlnode_get_attrib(identity, "category");
      idtype = xmlnode_get_attrib(identity, "type");
      if (purple_strequal(idcat, "auth") &&
          purple_strequal(idtype, "otr-prekey")) {
        find_connection_information_for(pc, from, data);
      }
    }
  }
}

static void
investigate_server_item(PurpleConnection *pc, const char *jid,
                        otrng_plugin_prekey_discovery_status *iq_status) {
  otrng_plugin_prekey_discovery_status *new_iq_handle =
      malloc(sizeof(otrng_plugin_prekey_discovery_status));
  new_iq_handle->next = receive_server_info;
  new_iq_handle->result_cb = iq_status->result_cb;
  new_iq_handle->context = iq_status->context;
  send_iq(pc, jid, NS_DISCO_INFO, new_iq_handle);
}

static void receive_server_items(PurpleConnection *pc, const char *type,
                                 const char *id, const char *from, xmlnode *iq,
                                 gpointer data) {
  xmlnode *query;

  if (purple_strequal(type, "result") &&
      (query = xmlnode_get_child(iq, "query"))) {
    xmlnode *item;

    for (item = xmlnode_get_child(query, "item"); item;
         item = xmlnode_get_next_twin(item)) {
      const char *jid = xmlnode_get_attrib(item, "jid");
      investigate_server_item(pc, jid, data);
    }
  }
}

static gboolean xmpp_iq_received(PurpleConnection *pc, const char *type,
                                 const char *id, const char *from,
                                 xmlnode *iq) {
  otrng_plugin_prekey_discovery_status *iq_status;

  iq_status = g_hash_table_lookup(iq_callbacks, id);
  if (!iq_status) {
    return FALSE;
  }

  otrng_plugin_prekey_discovery_status *copy =
      malloc(sizeof(otrng_plugin_prekey_discovery_status));
  copy->next = iq_status->next;
  copy->result_cb = iq_status->result_cb;
  copy->context = iq_status->context;

  g_hash_table_remove(iq_callbacks, id);

  copy->next(pc, type, id, from, iq, copy);

  return TRUE;
}

// Returns a new buffer containing the domain part of the jid
// It is the callers responsibility to free this
// If no delimiters are found it's assumed the full string is the domain
char *get_domain_from_jid(const char *jid) {
  char *current;
  char *start = (char *)jid;
  int len = 0;

  if (!start) {
    return NULL;
  }

  for (current = start; *current; current++) {
    if (*current == '@') {
      start = current + 1;
      break;
    }
  }

  for (current = start; *current; current++) {
    if (*current == '/') {
      break;
    }
    len++;
  }

  char *result = malloc(len + 1);
  if (!result) {
    return NULL;
  }
  memcpy(result, start, len);
  result[len] = '\0';
  return result;
}

int otrng_plugin_jabber_lookup_prekey_servers_for(PurpleAccount *account,
                                                  const char *who,
                                                  PrekeyServerResult result_cb,
                                                  void *context) {
  if (account == NULL || who == NULL) {
    return 0;
  }
  PurplePlugin *prpl = purple_plugins_find_with_id("prpl-jabber");
  if (prpl == NULL) {
    return 0;
  }
  PurpleConnection *pc = purple_account_get_connection(account);
  if (pc == NULL) {
    return 0;
  }

  char *nwho = g_strdup(purple_normalize(account, who));
  char *server = get_domain_from_jid(nwho);

  otrng_plugin_prekey_discovery_status *iq_handle =
      malloc(sizeof(otrng_plugin_prekey_discovery_status));
  iq_handle->next = receive_server_items;
  iq_handle->result_cb = result_cb;
  iq_handle->context = context;

  if (!iq_listening) {
    purple_signal_connect(prpl, "jabber-receiving-iq", iq_handle,
                          PURPLE_CALLBACK(xmpp_iq_received), NULL);
    iq_listening = TRUE;
  }

  send_iq(pc, server, NS_DISCO_ITEMS, iq_handle);

  free(server);
  g_free(nwho);
  return 1;
}

void otrng_plugin_prekey_discovery_jabber_load() {
  iq_callbacks = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

void otrng_plugin_prekey_discovery_jabber_unload() {
  g_hash_table_destroy(iq_callbacks);
  iq_callbacks = NULL;
}
