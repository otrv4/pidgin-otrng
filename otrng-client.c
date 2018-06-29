#include <stdio.h>

#include <libotr-ng/client.h>

#include "otrng-client.h"

char*
otrv4_client_adapter_privkey_fingerprint(const otr4_client_t *client)
{
    char *ret = NULL;

    otrv4_fingerprint_t our_fp = {0};
    if (otr4_client_get_our_fingerprint(our_fp, client))
        return NULL;

    ret = malloc(OTR4_FPRINT_HUMAN_LEN);
    if (!ret)
        return NULL;

    otr4_fingerprint_hash_to_human(ret, our_fp);
    return ret;
}

