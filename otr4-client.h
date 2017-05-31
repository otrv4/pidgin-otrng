#ifndef _OTR4_CLIENT_H_
#define _OTR4_CLIENT_H_

#include <glib.h>
#include <libotr/context.h>
#include <libotr4/client.h>

typedef struct {
  char *account;
  char *protocol;

  otr4_client_t *real_client;
} otr4_client_adapter_t;

typedef struct {
    char *account;
    char *protocol;
    char *peer;

    uint16_t their_instance_tag;
    uint16_t our_instance_tag;
} otr4_client_conversation_t;

typedef struct {
        /* Create a private key for the given accountname/protocol if
         * desired. */
        void (*create_privkey)(const otr4_client_adapter_t *);

        /* A connection has entered a secure state. */
        void (*gone_secure) (const otr4_client_conversation_t *);

        /* A connection has left a secure state. */
        void (*gone_insecure) (const otr4_client_conversation_t *);

        /* A fingerprint was seen in this connection. */
        void (*fingerprint_seen) (const otrv4_fingerprint_t, const otr4_client_conversation_t *);

        /* A OTR3 fingerprint was seen in this connection. */
        void (*fingerprint_seen_otr3) (const otrv3_fingerprint_t, const otr4_client_conversation_t *);

        /* Update the authentication UI and prompt the user to enter a shared secret.
         *      The sender application should call otrl_message_initiate_smp,
         *      passing NULL as the question.
         *      When the receiver application resumes the SM protocol by calling
         *      otrl_message_respond_smp with the secret answer. */
        void (*smp_ask_for_secret) (const otr4_client_conversation_t *);

        /* Same as smp_ask_for_secret but sender calls otrl_message_initiate_smp_q instead) */
        void (*smp_ask_for_answer) (const char* question, const otr4_client_conversation_t *);

        /* Update the authentication UI with respect to SMP events
         * These are the possible events:
         * - OTRL_SMPEVENT_CHEATED
         *      abort the current auth and update the auth progress dialog
         *      with progress_percent. otrl_message_abort_smp should be called to
         *      stop the SM protocol.
         * - OTRL_SMPEVENT_INPROGRESS       and
         *   OTRL_SMPEVENT_SUCCESS          and
         *   OTRL_SMPEVENT_FAILURE          and
         *   OTRL_SMPEVENT_ABORT
         *      update the auth progress dialog with progress_percent
         * - OTRL_SMPEVENT_ERROR
         *      (same as OTRL_SMPEVENT_CHEATED)
         * */
        void (*smp_update) (const otr4_smp_event_t event, const uint8_t progress_percent, const otr4_client_conversation_t *);
} otrv4_plugin_callbacks_t;

otr4_client_adapter_t*
otr4_client_adapter_new(const otrv4_callbacks_t *callbacks,
    OtrlUserState userstate, const char *protocol, const char *account);

void
otr4_client_adapter_free(otr4_client_adapter_t *client);

char*
otr4_client_adapter_query_message(const char *recipient,
                          const char* message,
                          otr4_client_adapter_t *client);

int
otr4_client_adapter_send(char **newmessage,
                 const char *message,
                 const char *recipient,
                 otr4_client_adapter_t *client);

int
otr4_client_adapter_receive(char **newmessage,
                    char **todisplay,
                    const char *message,
                    const char *recipient,
                    otr4_client_adapter_t *client);

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_adapter_t *client);

int
otr4_client_adapter_read_privkey_FILEp(otr4_client_adapter_t *client, FILE *privf);

int
otr4_client_generate_privkey(otr4_client_adapter_t *client);

const otr4_conversation_t *
otr4_client_adapter_get_conversation_from_connection(const otrv4_t *conn, const otr4_client_adapter_t *client);

int
otr4_client_adapter_disconnect(char **newmessage, const char *recipient,
                               otr4_client_adapter_t * client);

int otr4_client_adapter_smp_start(char **tosend, const char *recipient,
    const char *question, const unsigned char *secret, size_t secretlen,
    otr4_client_adapter_t * client);

int otr4_client_adapter_smp_respond(char **tosend, const char *recipient,
     const unsigned char *secret, size_t secretlen, otr4_client_adapter_t * client);

void otr4_callbacks_set(const otrv4_plugin_callbacks_t *otr4_callbacks);
void otrv4_userstate_create(void);
void otrv4_userstate_destroy(void);
otr4_client_adapter_t* otr4_client(const char *protocol, const char *accountname);
void otr4_privkey_read_FILEp(FILE *privf);
void otr4_privkey_write_FILEp(FILE *privf);

//TODO: UNUSED?
otr4_client_adapter_t* otr4_get_client(const otr4_client_conversation_t*);

#endif 
