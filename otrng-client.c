#include <stdio.h>

#include <libotr-ng/client.h>

#include "otrng-client.h"

char*
otrv4_client_adapter_privkey_fingerprint(const otrng_client_s *client)
{
    char *ret = NULL;

    otrv4_fingerprint_t our_fp = {0};
    if (otrng_client_get_our_fingerprint(our_fp, client))
        return NULL;

    ret = malloc(OTR4_FPRINT_HUMAN_LEN);
    if (!ret)
        return NULL;

    otrng_fingerprint_hash_to_human(ret, our_fp);
    return ret;
}

