#ifndef __MSG_H__
#define __MSG_H__

#define AES_KEY_128 16
#define BUFSIZE 256

enum MSG_TYPE {
    PUBLIC_KEY,
    SERV_PUBLIC_KEY,
    SERV_SECRET_KEY,
    CLNT_PUBLIC_KEY,
    CLNT_SECRET_KEY,
    PUBLIC_KEY_REQUEST,
    IV,
    // ENCRYPTED_KEY,
    ENCRYPTED_MSG,
    HASH,
};

typedef struct _APP_MSG_ {
    int type;
    unsigned char payload[BUFSIZE + BUFSIZE];
    int msg_len;
}APP_MSG;

#endif