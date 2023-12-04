#ifndef _AESENC_H_
#define _AESENC_H_

void handleErrors(void);
int encrypt_(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char *iv, unsigned char* ciphertext);
int decrypt_(unsigned char* ciphertext, int ciphertextg_len, unsigned char* key, unsigned char *iv, unsigned char* recovered);

#endif

