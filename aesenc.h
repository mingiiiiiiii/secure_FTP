#ifndef _AESENC_H_ // 중복 막으려고
#define _AESENC_H_

// #include "aesenc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define Ch(x, y, z)			((x & y) ^ (~(x) & (z)))
#define Maj(x, y, z)		(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sf(x, n)			(x >> n)

#define WE0(x)				(ROTR(x,  7) ^ ROTR(x, 18) ^ Sf(x, 3))
#define WE1(x)				(ROTR(x,  17) ^ ROTR(x, 19) ^ Sf(x, 10))

#define BS0(x)				((ROTR(x,  2)) ^ ROTR(x, 13) ^ ROTR(x,  22))
#define BS1(x)				(ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x,  25))

#define BLOCKBYTE 64
#define SHA256_DIGEST_BLOCKLEN 64
#define SHA256_DIGEST_VALUELEN 32

typedef unsigned char byte;
typedef unsigned int word;

#define IN 
#define OUT

#define ROTL(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))
#define ENDIAN_CHANGE(X)	((ROTL((X),  8) & 0x00ff00ff) | (ROTL((X), 24) & 0xff00ff00))
#define IPAD 0x36
#define OPAD 0x5c
#define BILLION 1000000000L

typedef struct
{
	word hash[8];
	word byte_msglen;
	byte buf[BLOCKBYTE];
}SHA256_INFO;

void M_SHA256_init(OUT SHA256_INFO* info);
void M_Block(IN word* const pt, OUT SHA256_INFO* info);
void M_SHA256_Process(IN byte* pt, IN word byte_msglen, OUT SHA256_INFO* info);
void M_SHA256_Final(OUT SHA256_INFO* info, OUT byte* hash_value);
void M_SHA256(IN byte* pt, IN unsigned long long byte_msglen, OUT byte* hash_value);

void handleErrors(void);
int _encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int _decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

#endif