#ifndef _ECDH_H_
#define _ECDH_H_

#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

struct derivedKey {
    char* secret;
    int length;
};

typedef struct derivedKey derivedKey;

EVP_PKEY* generateKey();
EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey);
derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey);

#endif