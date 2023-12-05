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

void read_childproc(int sig) {
    pid_t pid;
    int status;
    pid = waitpid(-1, &status, WNOHANG);
    printf("removed prod id: %d \n", pid);
}

int main(int argc, char *argv[]) {
    // ECDH
    BIO *bp_servPublicKey = NULL;      // for bio
    BIO *bp_clntPublicKey = NULL;
    EVP_PKEY *ecdh_servPrivateKey = generateKey();   // only one private key for server
    EVP_PKEY *ecdh_servPublicKey = extractPublicKey(ecdh_servPrivateKey);
    EVP_PKEY *ecdh_clntPublicKey = NULL;
    derivedKey* serverSecret = NULL;
    unsigned char serverSecretKey[16];  // session key

    int n;
    int servPublicKey_len;

    bp_servPublicKey = BIO_new(BIO_s_mem());
    if (!bp_servPublicKey) {
        error_handling("BIO_new(BIO_s_mem()) error");
    }

    if (PEM_write_bio_PUBKEY(bp_servPublicKey, ecdh_servPublicKey) != 1) {
        error_handling("ECDH PEM_write_bio_PUBKEY() error");
        BIO_free(bp_servPublicKey);
        // abort();
    }
    servPublicKey_len = BIO_pending(bp_servPublicKey);

    // socket
    int serv_sock = -1;
    int clnt_sock = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;

    // APP_MSG
    APP_MSG msg_in;
    APP_MSG msg_out;

    if (argc != 2) {
        printf("Usage : %s <port>\n", argv[0]);
		exit(1);
    }

    // multi process
    pid_t pid;
    struct sigaction act;
    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    int state = sigaction(SIGCHLD, &act, 0);

    printf("\n[PREPARING SOCKET]\n");
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) {
        error_handling("socket() error");
    }

    // set addr
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    // bind()
    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        error_handling("bind() error");
    }

    // listen()
    if (listen(serv_sock, 5) == -1) {
        error_handling("listen() error");
    }

    while (1) {
        // accept()
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1) {
            // error_handling("accept() error");
            continue;
        }
        else {
            printf("[NEW CLIENT CONNECTED]\n");
        }

        //todo ECDH를 위한 공개키/개인키 생성
        // 서버는 개인키 하나만 있으면 될듯?
        // 클라이언트의 공개키를 받아서 값 생성
        // 반대로 클라이언트는 서버의 공개키를 받아 생성

        pid = fork();

        if (pid == -1) {
            close(clnt_sock);
            continue;
        }

        if (pid == 0) {  // child process
            close(serv_sock);

            // read client request message
            memset(&msg_in, 0, sizeof(msg_in));
            n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
            msg_in.type = ntohl(msg_in.type);
            msg_in.msg_len = ntohl(msg_in.msg_len);
            if (n == -1) {
                error_handling("readn() error");
            }
            else if (n == 0) {
                error_handling("reading EOF");
            }

            if (msg_in.type != PUBLIC_KEY_REQUEST) {
                error_handling("client first message must be PUBLIC_KEY_REQUEST");
            }
            else {
                // read client's public key
                bp_clntPublicKey = BIO_new_mem_buf(msg_in.payload, msg_in.msg_len);
                if (!bp_clntPublicKey) {
                    error_handling("BIO_new_mem_buf() error");
                }

                ecdh_clntPublicKey = PEM_read_bio_PUBKEY(bp_clntPublicKey, NULL, NULL, NULL);
                if (!ecdh_clntPublicKey) {
                    error_handling("PEM_read_bio_PUBKEY() error");
                    BIO_free(bp_clntPublicKey);
                }

                //! debug
                serverSecret = deriveShared(ecdh_clntPublicKey, ecdh_servPrivateKey);
                memcpy(serverSecretKey, serverSecret->secret, 16);
                for (int cnt = 0; cnt < 16; cnt++) {
                    printf("%02X ", serverSecretKey[cnt]);
                } printf("\n");


                // set-up process for send public key to client
                memset(&msg_out, 0, sizeof(msg_out));
                msg_out.type = PUBLIC_KEY;
                msg_out.type = htonl(msg_out.type);

                // already packing in line 38

                BIO_read(bp_servPublicKey, msg_out.payload, servPublicKey_len);
                msg_out.msg_len = ntohl(servPublicKey_len);
                n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                if (n == -1) {
                    error_handling("writen() error");
                }

            }

        
            //! do everything
            
        }
        else {  // parent process
            close(clnt_sock);
        }


    }

    // close ?? ERROR ??? 나중에 에러 레이블로 하려나
    
    close(serv_sock);

    return 0;
}
