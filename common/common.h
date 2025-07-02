#ifndef USE_OPENSSL_COMMON_H
#define USE_OPENSSL_COMMON_H

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "rsa_pss.h"

int sign(OSSL_LIB_CTX *libctx, unsigned char **sig, size_t *sig_len, char *test_message, size_t message_len);
int verify(OSSL_LIB_CTX *libctx, const unsigned char *sig, size_t sig_len, char *test_message, size_t message_len);

#endif //USE_OPENSSL_COMMON_H
