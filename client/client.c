#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "ECDH.h"
#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

void error_handling(char *message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

typedef struct derivedKey derivedKey;

int main(int argc, char* argv[]) {
    //ECDH
    BIO* bp_clntPublicKey = NULL;
    BIO* bp_servPublicKey = NULL;
    EVP_PKEY *ecdh_clntPrivateKey = generateKey();
    EVP_PKEY *ecdh_clntPublicKey = extractPublicKey(ecdh_clntPrivateKey);
    EVP_PKEY *ecdh_servPublicKey = NULL;
    derivedKey* clientSecret = NULL;
    unsigned char clientSecretKey[16];  // session key

    int n;
    int clntPublicKey_len;

    // socket
    int sock = -1;
	struct sockaddr_in serv_addr;

	// APP_MSG
	APP_MSG msg_in;
    APP_MSG msg_out;

    if(argc!=3){
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

    printf("[PREPARING SOCKET]");
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        error_handling("socket() error");
    }

    // set addr
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));
	
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        error_handling("connect() error!");
    }

    // set-up process for send public key to server and request server's public key
    // sending PUBLIC_KEY_REQUEST msg with client public key
    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = PUBLIC_KEY_REQUEST;
    msg_out.type = htonl(msg_out.type);

    bp_clntPublicKey = BIO_new(BIO_s_mem());
    if (!bp_clntPublicKey) {
        error_handling("BIO_new(BIO_s_mem()) error");
    }

    if (PEM_write_bio_PUBKEY(bp_clntPublicKey, ecdh_clntPublicKey) != 1) {
        error_handling("ECDH PEM_write_bio_PUBKEY() error");
        BIO_free(bp_clntPublicKey);
        // abort();
    }
    clntPublicKey_len = BIO_pending(bp_clntPublicKey);

    BIO_read(bp_clntPublicKey, msg_out.payload, clntPublicKey_len);
    msg_out.msg_len = ntohl(clntPublicKey_len);
    n = writen(sock, &msg_out, sizeof(APP_MSG));
    if (n == -1) {
        error_handling("writen() error");
    }

    // set-up process for receive server public key
    memset(&msg_in, 0, sizeof(msg_in));
    n = readn(sock, &msg_in, sizeof(APP_MSG));
    msg_in.type = ntohl(msg_in.type);
    msg_in.msg_len = ntohl(msg_in.msg_len);
    if (n == -1) {
        error_handling("readn() error");
    }
    else if (n == 0) {
        error_handling("reading EOF");
    }

    if (msg_in.type != PUBLIC_KEY) {
        error_handling("server first message must be PULBIC_KEY");
    }
    else {
        printf("send server public key\n");
        // read server's public key
        bp_servPublicKey = BIO_new_mem_buf(msg_in.payload, msg_in.msg_len);
        if (!bp_servPublicKey) {
            error_handling("BIO_new_mem_buf() error");
        }

        ecdh_servPublicKey = PEM_read_bio_PUBKEY(bp_servPublicKey, NULL, NULL, NULL);
        if (!ecdh_servPublicKey) {
            error_handling("PEM_read_bio_PUBKEY() error");
            BIO_free(bp_servPublicKey);
        }

        //! debug
        clientSecret = deriveShared(ecdh_servPublicKey, ecdh_clntPrivateKey);
        memcpy(clientSecretKey, clientSecret->secret, 16);
        for (int cnt = 0; cnt < 16; cnt++) {
            printf("%02X ", clientSecretKey[cnt]);
        } printf("\n");
    }

    // //! debug
    // serverSecret = deriveShared(ecdh_clntPublicKey, ecdh_servPrivateKey);


}