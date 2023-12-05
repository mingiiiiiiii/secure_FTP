#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h> // 파일 입출력 헤더

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

#define BUF_SIZE 128
#define IDPW_SIZE 16

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

// 클라이언트 실행 파일 생성 명령어 : gcc aesenc.c readnwrite.c clnt.c -o clnt -lcrypto
// -o clnt : 생성할 실행파일의 이름
// -lcrypto : OpenSSL 사용을 위한 명령어

// 클라이언트 실행 명령어 : ./(실행파일 이름) (IP) (port number) 
//                    ex) ./clnt 127.0.0.1 9190

int main(int argc, char* argv[])
{
    int sock; // 클라이언트는 소켓 하나만 
    struct sockaddr_in serv_addr;
    char message[BUF_SIZE+1];
    int str_len, cnt_i;
    int msg_type = INPUT_IDPW;

    APP_MSG id;
    APP_MSG pw;
    APP_MSG msg_in;
    APP_MSG msg_out;

    char id_array[IDPW_SIZE] = {0, };
    char pw_array[IDPW_SIZE] = {0, };
    char enc_filename[BUF_SIZE] = {0, };
    char dec_filename[BUF_SIZE] = {0, };
    
    char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0, };
    unsigned char encrypted_key[BUFSIZE] = {0, };

    unsigned char key[AES_KEY_128] = {0, };
    unsigned char iv[AES_KEY_128] = {0, };
    unsigned char hash1[32] = {0, };
    unsigned char hash2[32] = {0, };

    BIO *rpub = NULL;
    RSA *rsa_pubkey = NULL;
    char down_dir[40] = "./clntsavedata/";
    int down_dir_len = strlen(down_dir);
    int len = 0;
    int n;
    int plaintext_len;
    int ciphertext_len;
    

    // 전송되는 데이터들을 인증하기위해 SHA-256 자체적으로 구현 후 사용(aesenc.c 에 SHA-256 함수 구현)
    if (argc != 3)
    {
        printf("Usage: %s <IP><port>\n", argv[0]);
        exit(1);
    }

    RAND_poll();
    RAND_bytes(key, sizeof(key)); // 난수 생성, 랜덤한 세션 키 생성
    
    for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("connect() error");
    }
    else
    {
        printf("Connected.............\n");
    }

    // setup process
    // sending PUBLIC_KEY_REQUEST msg
    // 서버로 공개키 요청 메시지 전송
    memset(&msg_out, 0, sizeof(msg_out)); // 0 초기화
    msg_out.type = PUBLIC_KEY_REQUEST; // 타입 설정
    msg_out.type = htonl(msg_out.type);

    n = writen(sock, &msg_out, sizeof(APP_MSG)); // 소켓으로 전달 
    if (n == -1)
    {
        error_handling("writen() error");
    }

    //서버로부터의 공개키 메시지 수신
    //receiving PUBLIC_KEY msg
    memset(&msg_in, 0, sizeof(APP_MSG)); 
    n = readn(sock, &msg_in, sizeof(APP_MSG)); 
    msg_in.type = ntohl(msg_in.type); 
    msg_in.msg_len = ntohl(msg_in.msg_len); 

    if (n == -1)
    {
        error_handling("readn() error");
    }
    else if (n == 0)
    {
        error_handling("reading EOF");
    }

    if (msg_in.type != PUBLIC_KEY)
    {
        error_handling("message error");
    }
    else
    {
        // 공개키 받았으므로
        // 서버로부터의 공개키 메시지를 RSA 타입으로 변환
        rpub = BIO_new_mem_buf(msg_in.payload, -1);
        BIO_write(rpub, msg_in.payload, msg_in.msg_len);
        if (!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)) // 공개키 뽑아오기 // rpub에 들어있는 데이터를 rsa_pubkey로 전송
        {
            error_handling("PEM_read_bio_RSAPublicKey() error");
        }
    }
    
    //sending ENCRYPTED_KEY msg
    //클라이언트는 랜덤하게 생성한 키를 서버의 공개키로 암호화하여 서버로 전송
    memset(&msg_out, 0, sizeof(APP_MSG));
    msg_out.type = ENCRYPTED_KEY;
    msg_out.type = htonl(msg_out.type);
    // 공개키를 사용해 세션키를 암호화한 후 payload 에 저장해서 보낸다.
    msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
    msg_out.msg_len = htonl(msg_out.msg_len);

    n = writen(sock, &msg_out, sizeof(APP_MSG));

    if (n == -1)
    {
        error_handling("writen() error");
    }

    // 서버와 클라이언트의 키가 제대로 전송되어 같은지 확인용
    printf("session key = ");
    for (int i = 0; i < AES_KEY_128; i++)
    {
        printf("%02X ", key[i]);
    }
    printf("\n");

    //Login process
    // ID/PW 입력 예시
    //user.txt 안에 ID : PW 형태로로 저장
    // ex) ID : qkrqhtjs
    //     PW : 123456
    // 형태로 입력시 user.txt ID : PW 기준으로 존재하면 로그인 성공 존재하지 않으면 로그인 실패
    msg_type = LOGIN_FAIL;
    while(msg_type != LOGIN_SUCCESS)
    {  
        int select = 0;
        int ct_id_len = 0;
        int ct_pw_len = 0;
        switch (msg_type)
        {
        case INPUT_IDPW: // ID/PW 입력 부분
            msg_type = LOGIN_MSG;
            printf("Input ID/PW\n");
            memset(&id, 0, sizeof(id));
            memset(&pw, 0, sizeof(pw));

            // ID/PW 입력
            printf("ID : ");
            if (fgets(id_array, IDPW_SIZE + 1, stdin) == NULL)
                break;
            printf("PW : ");
            if (fgets(pw_array, IDPW_SIZE + 1, stdin) == NULL)
                break;

            // 개행도 배열에 들어가므로 \0로 교체
            ct_id_len = strlen(id_array);
            if (id_array[ct_id_len - 1] == '\n')
                id_array[ct_id_len - 1] = '\0';
            if (strlen(id_array) == 0)
                break;

            ct_pw_len = strlen(pw_array);
            if (pw_array[ct_pw_len - 1] == '\n')
                pw_array[ct_pw_len - 1] = '\0';
            if (strlen(pw_array) == 0)
                break;

            // 서버로 ID/PW 암호화, 태그 생성 후 전송
            M_SHA256(id_array, strlen(id_array), hash1);
            ct_id_len = _encrypt((unsigned char *)id_array, ct_id_len, key, iv, id.payload);
            id.type = msg_type;
            id.type = htonl(id.type);
            id.msg_len = htonl(ct_id_len);
            
            M_SHA256(pw_array, strlen(pw_array), hash2);
            ct_pw_len = _encrypt((unsigned char *)pw_array, ct_pw_len, key, iv, pw.payload);
            pw.type = msg_type;
            pw.type = htonl(pw.type);
            pw.msg_len = htonl(ct_pw_len);

            writen(sock, &id, sizeof(APP_MSG));
            writen(sock, &pw, sizeof(APP_MSG));
            writen(sock, hash1, sizeof(hash1));
            writen(sock, hash2, sizeof(hash2));
            break;
        case LOGIN_FAIL:
            // 로그인 실패시 재입력, ID/PW 등록 선택
            
            printf("1 : ENROLLMENT USER     2 : Try to log in again >>> "); // 1 or 2 입력
            scanf("%d", &select);
            // ID/PW 등록 선택
            if (select == 1)
            {
                msg_type = ENROLL_MSG;
                printf("Enter ID/Password to register\n");
                getchar();
                memset(&id, 0, sizeof(id));
                memset(&pw, 0, sizeof(pw));

                // 등록할 ID/PW 입력
                printf("ID : ");
                fgets(id_array, IDPW_SIZE + 1, stdin);
                printf("PW : ");
                fgets(pw_array, IDPW_SIZE + 1, stdin);

                id.msg_len = strlen(id_array);
                pw.msg_len = strlen(pw_array);

                id_array[id.msg_len - 1] = '\0';
                pw_array[pw.msg_len - 1] = '\0';
                
                M_SHA256(id_array, strlen(id_array), hash1);
                M_SHA256(pw_array, strlen(pw_array), hash2);

                ct_id_len = _encrypt((unsigned char *)id_array, id.msg_len, key, iv, id.payload);
                ct_pw_len = _encrypt((unsigned char *)pw_array, pw.msg_len, key, iv, pw.payload);

                id.msg_len = htonl(ct_id_len);
                pw.msg_len = htonl(ct_pw_len);

                id.type = msg_type;
                pw.type = msg_type;

                id.type = htonl(id.type);
                pw.type = htonl(pw.type);
                writen(sock, &id, sizeof(APP_MSG));
                writen(sock, &pw, sizeof(APP_MSG));
                writen(sock, hash1, sizeof(hash1));
                writen(sock, hash2, sizeof(hash2));
                msg_type = INPUT_IDPW;
                break;
            }
            else if (select == 2) // 재입력 선택
            {
                getchar();
                msg_type = INPUT_IDPW;
                break;
            }
            else
            {
                printf("Input Error\n");
                msg_type = LOGIN_FAIL;
                break;
            }
        case LOGIN_SUCCESS: 
            msg_type = LOGIN_SUCCESS; // 로그인 성공
            break;
        default:
            break;
        }
        if (msg_type != LOGIN_SUCCESS && msg_type != INPUT_IDPW)
        {
            memset(&msg_in, 0, sizeof(APP_MSG));
            readn(sock, &msg_in, sizeof(APP_MSG));
            msg_in.type = ntohl(msg_in.type);
            msg_type = msg_in.type;
        }
    }
    ////////////////////////////////////////////////////////////
    printf("Login--------------------------------------\n");

    msg_type = WAIT;
    // 명령어 입력
    while(msg_type != QUIT)
    {
        char command[10];
        int fd = -1;
        char file_name1[20] = {0, };
        char enc_file_name1[20] = {0, };
        char file_name2[20] = {0, };
        char enc_file_name2[20] = {0, };

        char buf[BUFSIZE];
        unsigned int size = 0;
        int file_len = 0;
        // 4가지 중 하나 입력
        printf("Input Command\n");
        printf("1. UP    2. DOWN     3. LIST     4. QUIT : "); // up, down, list, quit입력을 통해 실행
        scanf("%s", command);
        command[strlen(command)] = '\0';
        // 입력받은 명령어에 따라 메시지 타입 선택
        if (strcmp(command, "up") == 0 || strcmp(command, "UP") == 0)
            msg_type = UP;
        else if (strcmp(command, "down") == 0 || strcmp(command, "DOWN") == 0)
            msg_type = DOWN;
        else if (strcmp(command, "list") == 0 || strcmp(command, "LIST") == 0)
            msg_type = LIST;
        else if (strcmp(command, "quit") == 0|| strcmp(command, "QUIT") == 0)
            msg_type = QUIT;
        else
            msg_type = WAIT;
        
        // 입력받은 명령어에 따른 클라이언트의 동작과정
        switch (msg_type)
        {
        case WAIT:
            break;
        case UP: // 파일 업로드 실행파일, C파일이 존재하는 폴더에 있는 파일만 업로드 가능
            // 업로드할 파일 이름과 서버에 저장될 이름 입력
            // 폴더내 파일 script.txt 만있으므로
            // Upload File Name는 script.txt입력
            // Save File Name은 원하는 이름 입력
            // 20-byte로 입력 제한
            for (int i = down_dir_len; i < sizeof(down_dir); i++)
                down_dir[i] = 0;
            memset(file_name1, 0, sizeof(file_name1));
            memset(file_name2, 0, sizeof(file_name2));
            printf("Upload File Name : ");
            scanf("%s", file_name1);
            printf("Save File Name : ");
            scanf("%s", file_name2);
            file_name1[strlen(file_name1)] = '\0';
            file_name2[strlen(file_name2)] = '\0';

            len = strlen(down_dir);
            for (int i = 0; i < len; i++)
                down_dir[len + i] = file_name1[i];


            // 업로드할 파일 오픈
            fd = open(down_dir, O_RDONLY, S_IRWXU);
            if (fd == -1)
            {
                //! error_handling("open() error");
                printf("open() error\n");
                break;
            }
            // 파일 이름 보내기
            memset(&msg_out, 0, sizeof(APP_MSG));
            memcpy(enc_file_name2, file_name2, strlen(file_name2));
            M_SHA256(enc_file_name2, strlen(enc_file_name2), hash1);
            plaintext_len = _encrypt((unsigned char*)enc_file_name2, strlen(enc_file_name2), key, iv, msg_out.payload);
            msg_out.type = htonl(UP);
            msg_out.msg_len = htonl(plaintext_len);
            writen(sock, &msg_out, sizeof(APP_MSG));
            writen(sock, hash1, sizeof(hash1));
            // 파일 내용 보내기
            // 일정 크기만큼 잘라서 파일내용을 보냄
            while (1)
            {
                memset(buf, 0x00, BUFSIZE);
                memset(hash1, 0, sizeof(hash1));
                file_len = readn(fd, buf, BUFSIZE);
                if (file_len == 0)
                {
                    printf("finish file\n");
                    break;
                }
                M_SHA256(buf, file_len, hash1);
                file_len = _encrypt((unsigned char*)buf, file_len, key, iv, msg_out.payload);
                msg_out.msg_len = htonl(file_len);
                msg_out.type = htonl(FILE_DATA);
                writen(sock, &msg_out, sizeof(APP_MSG));
                writen(sock, hash1, sizeof(hash1));
            }
            // 파일의 내용 다 보낸후 파일 전송이 끝났다는 메시지 전송
            memset(&msg_out, 0, sizeof(APP_MSG));
            msg_out.type = htonl(SEND_FINISH);
            writen(sock, &msg_out, sizeof(APP_MSG));
            close(fd);
            printf("Upload success\n");
            msg_type = WAIT; // 대기 상태로 변환
            
            break;
        case DOWN: // 파일 다운로드 실행파일, C파일이 존재하는 폴더에있는 파일만 다운로드 가능
            // 다운로드하려는 파일 이름과 다운로드한 파일을 저장할 이름 입력
            // 폴더내 존재하는 파일 script.txt 이므로 다운로드 파일 이름에 script.txt입력
            // Save File Name 원하는 이름 입력 
            // 20-byte 내로 입력 제한
            for (int i = down_dir_len; i < sizeof(down_dir); i++)
                down_dir[i] = 0;
            memset(file_name1, 0, sizeof(file_name1));
            memset(file_name2, 0, sizeof(file_name2));
            printf("Download File Name : ");
            scanf("%s", file_name1);
            printf("Save File Name : ");
            scanf("%s", file_name2);
            file_name1[strlen(file_name1)] = '\0';
            file_name2[strlen(file_name2)] = '\0';

            len = strlen(down_dir);
            for (int i = 0; i < len; i++)
                down_dir[len + i] = file_name2[i];

            fd = open(down_dir, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
            

            // 파일 이름 보내기
            memset(&msg_out, 0, sizeof(APP_MSG));
            memset(hash1, 0, sizeof(hash1));
            memcpy(enc_file_name1, file_name1, strlen(file_name1));

            M_SHA256(enc_file_name1, strlen(enc_file_name1), hash1);
            plaintext_len = _encrypt((unsigned char*)enc_file_name1, strlen(enc_file_name1), key, iv, msg_out.payload);
            msg_out.type = htonl(DOWN);
            msg_out.msg_len = htonl(plaintext_len);
            writen(sock, &msg_out, sizeof(APP_MSG));
            writen(sock, hash1, sizeof(hash1));
            ///////////////////////////////////////////////
            // 파일 존재 여부/////
            memset(&msg_in, 0, sizeof(APP_MSG));
            readn(sock, &msg_in, sizeof(APP_MSG));
            msg_in.type = ntohl(msg_in.type);
            // printf("msg_in type = %d\n", msg_in.type);
            if (msg_in.type == NONE_FILE) // 파일 존재 X
            {
                printf("No exist file\n");
                msg_type = DOWN;
                break;
            }
            else if (msg_in.type == EX_FILE) // 파일 존재 O
            {
                printf("Exist File\n");
            }
            else {

                printf("nothing done\n");
            }
            // 파일 다운로드
            // 다운로드받는 파일의 내용을 일정 크기만큼 잘라서 반복해서 받는다
            // 전송받는 파일은 암호화되서 전송된다.
            while (1)
            {
                memset(&msg_in, 0, sizeof(APP_MSG));
                memset(buf, 0, sizeof(buf));
                memset(hash1, 0, sizeof(hash1));
                memset(hash2, 0, sizeof(hash2));
                readn(sock, &msg_in, sizeof(APP_MSG));
                msg_in.msg_len = ntohl(msg_in.msg_len);
                msg_in.type = ntohl(msg_in.type);
                if (msg_in.type == EOF | msg_in.type == 0)
                {
                    break;
                }
                if (msg_in.type == FILE_DATA)
                {
                    readn(sock, hash1, sizeof(hash1));
                    file_len = _decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char *)buf);
                    M_SHA256(buf, strlen(buf), hash2);
                    // 전송된 데이터의 태그 체크를 통해 인증
                    if (!strcmp(hash1, hash2))
                    {
                        printf("not hash\n");
                        break;
                    }
                    writen(fd, buf, file_len);
                }
                else if (msg_in.type == SEND_FINISH) // 전송 끝
                {
                    msg_type = WAIT;
                    break;
                }
            }
            printf("Download finish\n");
            close(fd);
            break;
        case LIST: // savedata 폴더의 파일 리스트 전송
            memset(&msg_out, 0, sizeof(APP_MSG));
            msg_out.type = msg_type;
            msg_out.type = htonl(msg_out.type);
            writen(sock, &msg_out, sizeof(APP_MSG));
            msg_type = WAIT;
            // 여러개의 파일 리스트를 하나씩 받아옴
            while(1)
            {
                memset(&msg_in, 0, sizeof(APP_MSG));
                memset(hash1, 0, sizeof(hash1));
                memset(hash2, 0, sizeof(hash2));
                readn(sock, &msg_in, sizeof(APP_MSG));
                

                msg_in.type = ntohl(msg_in.type);
                msg_in.msg_len = ntohl(msg_in.msg_len);
                if (msg_in.type == SEND_FINISH) // 리스트 전송 끝
                {
                    msg_type = WAIT;
                    break;
                }
                else if (msg_in.type != SEND_FINISH)
                {
                    // 받아온 파일 이름을 하나씩 인증후 출력
                    readn(sock, hash1, sizeof(hash1));
                    ciphertext_len = _decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)dec_filename);
                    M_SHA256(dec_filename, ciphertext_len, hash2);

                    for (int i = 0; i < 32; i++)
                    {
                        if (hash1[i] != hash2[i])
                        {
                            printf("not hash\n");
                            msg_type = WAIT;
                            break;
                        }
                    }
                    printf("file name : %s\n", dec_filename);
                    memset(dec_filename, 0, sizeof(dec_filename));
                }
                
            }
            printf("list finish\n");\
            msg_type = WAIT;
            break;
        case QUIT:
            msg_type = QUIT; // 클라이언트 종료 명령어
            memset(&msg_out, 0, sizeof(APP_MSG));
            msg_out.type = msg_type;
            msg_out.type = htonl(msg_out.type);
            writen(sock, &msg_out, sizeof(APP_MSG)); // 서버로 종료 메시지 전송
            break;
        default:
            break;
        }
    }
    printf("QUIT\n"); // 클라이언트 종료
    close(sock);

    return 0;

}