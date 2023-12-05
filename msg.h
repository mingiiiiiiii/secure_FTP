#ifndef __MSG_H__
#define __MSG_H__

#define AES_KEY_128 16
#define BUFSIZE 512
#define AES_BLOCK_LEN 16


enum MSG_TYPE
{
    PUBLIC_KEY,
    SECRET_KEY,
    PUBLIC_KEY_REQUEST,
    IV,
    ENCRYPTED_KEY,
    ENCRYPTED_MSG,
    LOGIN_MSG,      // 로그인 시도
    ENROLL_MSG,     // 사용자 등록 요청 메세지
    ENROLL_SUCCESS, // 사용자 등록 성공
    LOGIN_SUCCESS,  // 로그인 성공
    LOGIN_FAIL,     // 로그인 실패
    INPUT_IDPW,     // 아이디/패스워드 입력
    TYPE_ERROR,     // 타입 에러
    NONE            // 없음
};

enum COMMAND
{
    LIST,
    SEND_LIST,
    SEND_FINISH,
    UP,
    FILE_NAME,
    FILE_DATA,
    DOWN,
    EX_FILE,
    NONE_FILE,
    DOWN_FILE,
    WAIT,
    QUIT
};

typedef struct _APP_MSG_
{
    int type;
    unsigned char payload[BUFSIZE + AES_BLOCK_LEN];
    int msg_len;
}APP_MSG;

#endif