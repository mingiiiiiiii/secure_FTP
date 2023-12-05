#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h> // file lisg in dir
#include <fcntl.h> // 파일 입출력 헤더

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"


#define BUF_SIZE 128
#define IDPW_SIZE 32

void error_handling(char *msg);
int rsaes_generator();
int check_user(char *id, char *pw);
void enrollment_user(char *id, char *pw);
static int _pad_unknopwn(void);

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

void read_childproc(int sig); // 운영체제가 직접적으로 자식프로세스가 종료됬을때 호출해준다.

#define BUF_SIZE 128

// 서버 실행 파일 생성 명령어 : gcc aesenc.c readnwrite.c serv.c -o serv -lcrypto
// -o serv : 생성할 실행파일의 이름
// -lcrypto : OpenSSL 사용을 위한 명령어

// 서버 실행 명령어 : ./serv (port number)
//               ex) ./serv 9190

int main(int argc, char* argv[])
{
    int serv_sock; // listening socket
    int clnt_sock; // accept 으로 받는 파일 디스크립트
    char message[BUF_SIZE+1];
    int str_len, cnt_i;
    int msg_type;
    struct sockaddr_in serv_addr; // 바인드함수용
    struct sockaddr_in clnt_addr; // 클라이언트 주소정보 저장
    socklen_t clnt_addr_size;
    char recv_id[IDPW_SIZE] = {0, };
    char recv_pw[IDPW_SIZE] = {0, };
    char file_name[BUF_SIZE] = {0, };
    APP_MSG id;
    APP_MSG pw;
    APP_MSG msg_in;
    APP_MSG msg_out;

    char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0, };
    int n;
    int len;
    int plaintext_len;
    int ciphertext_len;
    int publickey_len;
    int encryptedkey_len;
    
    char down_dir[40] = "./serversavedata/";
    int down_dir_len = strlen(down_dir);

    unsigned char key[AES_KEY_128] = {0, };
    unsigned char iv[AES_KEY_128] = {0, };
    unsigned char buffer[BUFSIZE] = {0, };
    unsigned char hash1[32] = {0, };
    unsigned char hash2[32] = {0, };

    unsigned char id_hash[32] = {0, };
    unsigned char pw_hash[32] = {0, };

    BIO *bp_public = NULL, *bp_private = NULL;
    BIO *pub = NULL;
    RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    pid_t pid;
    struct sigaction act;
    int state;

    DIR *dir;
    struct dirent *ent;
    
    
    if (argc != 2)
    {
        fprintf(stderr, "%s <port>\n", argv[0]);
    }

    RAND_poll();
    // iv값 생성
    for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
        iv[cnt_i] = (unsigned char)cnt_i;
    }

    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    state = sigaction(SIGCHLD, &act, 0);

    rsaes_generator(); // RSAES 공개키 개인키 생성

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1])); 

    if (bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }

    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }
    

    while (1)
    {
        // 클라이언트와 소켓 연결
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("New client connected\n");
        }

        // 공개키 읽기
        bp_public = BIO_new_file("./serversavedata/public.pem", "r");
        if (!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL)) // 공개키 정보 저장
        {
            goto err;
        }
        // 개인키 읽기
        bp_private = BIO_new_file("./serversavedata/private.pem", "r");
        if (!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)) // 개인키 정보 저장
        {
            goto err;
        }
        // 클라이언트로부터의 공개키 요청 메시지를 수신
        memset(&msg_in, 0, sizeof(APP_MSG));
        n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len); // 공개키 요청 수신
        if (n == -1)
        {
            error_handling("readn() error");
        }
        else if (n == 0)
        {
            error_handling("reading EOF");
        }
        ///////////////////////////////////////////////////

        if (msg_in.type != PUBLIC_KEY_REQUEST)
        {
            error_handling("message error 1");
        }
        else
        {
            // 공개키를 메시지에 적재하여 클라이언트로 전송
            // 공개키 보내기위한 준비 과정
            memset(&msg_out, 0, sizeof(APP_MSG));
            msg_out.type = PUBLIC_KEY;
            msg_out.type = htonl(msg_out.type);
            // 공개키를 읽어 전송
            pub = BIO_new(BIO_s_mem()); 
            PEM_write_bio_RSAPublicKey(pub, rsa_pubkey); 
            publickey_len = BIO_pending(pub); 

            BIO_read(pub, msg_out.payload, publickey_len); 
            msg_out.msg_len = publickey_len;
            msg_out.msg_len = htonl(msg_out.msg_len);
            

            n = writen(clnt_sock, &msg_out, sizeof(APP_MSG)); // 공개키 전송
            if (n == -1)
            {
                error_handling("writen() error");
                break;
            }
        }

        // 클라이언트로부터의 암호화된 세션키 수신, 복호화하여 세션키 복원
        memset(&msg_in, 0, sizeof(APP_MSG));
        n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

        if (msg_in.type != ENCRYPTED_KEY)
        {
            error_handling("message error 2");
        } 
        else
        {
            encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING); // 페이로드에 있는 데이터를 복호화해 버퍼에 복호화된 키가 들어감
            memcpy(key, buffer, encryptedkey_len); // 버퍼에 있는 키를 key변수에 옮긴다
        }
        
        // 서버로 전송된 복호화된 키 출력
        printf("session key = ");
        for (int i = 0; i < AES_KEY_128; i++)
        {
            printf("%02X ", key[i]);
        }
        printf("\n");
        //////////////////////////////////////////////////////////////////////////
        if (clnt_sock == -1)
        {
            continue;
        }
        else
        {
            printf("New client connected\n");
        }
        // 자식 프로세스 생성
        pid = fork();
        // 자식 프로세스가 하는 작동
        if (pid == 0) // child process
        {
            close(serv_sock); // 서버 소켓 필요없으므로 제거

            // 클라이언트 로그인 과정 메시지 수신 및 기능
            while(msg_type != LOGIN_SUCCESS)
            {
                int n = 0;
                int pt_id_len = 0;
                int pt_pw_len = 0;

                // 클라이언트로부터 메시지 수신
                n = readn(clnt_sock, &id, sizeof(APP_MSG));
                if (n == -1)
                {
                    error_handling("readn() error");
                    break;
                }
                else if (n == 0)
                    break;
                
                n = readn(clnt_sock, &pw, sizeof(APP_MSG));
                if (n == -1)
                {
                    error_handling("readn() error");
                    break;
                }
                else if (n == 0)
                    break;

                id.type = ntohl(id.type);
                pw.type = ntohl(pw.type);

                id.msg_len = ntohl(id.msg_len);
                pw.msg_len = ntohl(pw.msg_len);
                if (id.type == pw.type)
                {
                    msg_type = id.type;
                }
                else // ID, PW의 메시지 타입이 다르면 에러 메시지 전송
                {
                    msg_type = TYPE_ERROR;
                }
                readn(clnt_sock, id_hash, sizeof(id_hash));
                readn(clnt_sock, pw_hash, sizeof(pw_hash));

                pt_id_len = _decrypt(id.payload, id.msg_len, key, iv, (unsigned char *)recv_id);
                pt_pw_len = _decrypt(pw.payload, pw.msg_len, key, iv, (unsigned char *)recv_pw);
                
                // 전송된 데이터 인증을 위핸 SHA-256 태그 생성
                M_SHA256(id.payload, pt_id_len, hash1);
                M_SHA256(pw.payload, pt_pw_len, hash2);
                // 태그 비교
                if (!strcmp(id_hash, hash1))
                {
                    printf("not id hash\n");
                    msg_type = WAIT;
                    continue;
                }

                if (!strcmp(pw_hash, hash2))
                {
                    printf("not pw hash\n");
                    msg_type = WAIT;
                    continue;
                }

                switch (msg_type)
                {
                case LOGIN_MSG: // 로그인 메시지 수신시 동작
                    // 받은 ID/PW user.txt에 저장되어 있는지 확인
                    n = check_user(recv_id, recv_pw);
                    if (n == 1) // ID/PW 존재시 동작
                    {
                        // 로그인 성공 메시지 전송
                        msg_type = LOGIN_SUCCESS;
                        memset(&msg_out, 0, sizeof(APP_MSG));
                        msg_out.type = msg_type;
                        msg_out.type = htonl(msg_out.type);
                        writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                    }
                    else if (n == 0)
                    {
                        // 로그인 실패 메시지 전송
                        printf("login fail\n");
                        msg_type = LOGIN_FAIL;
                    }
                    break;
                case ENROLL_MSG: // ID/PW 등록 메시지 수신시 동작
                    enrollment_user(recv_id, recv_pw); // ID/PW 등록
                    printf("Enrollment succcess\n");
                    msg_type = ENROLL_SUCCESS;
                    break;
                case TYPE_ERROR: // 에러 메시지 전송
                    printf("Type Error\n");
                    msg_type = TYPE_ERROR;
                    break;
                default:
                    break;
                }
                // 로그인 성공 메시지 제외한 메시지들 전송과정
                if (msg_type != LOGIN_SUCCESS)
                {
                    memset(&msg_out, 0, sizeof(APP_MSG));
                    msg_out.type = msg_type;
                    msg_out.type = htonl(msg_out.type);
                    writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                    msg_type = NONE;
                }
            }
            //////////////////////////////////////////////////////////////
            printf("Login ------------------------------------------\n");
            
            msg_type = WAIT;
            // 명령어 메시지 수신
            while (msg_type != QUIT)
            {
                int fd = -1;
                char *save_name = NULL;
                char file_name1[20] = {0, };
                char dec_file_name1[20] = {0, };
                char file_name2[20] = {0, };
                char dec_file_name2[20] = {0, };
                char buf[BUFSIZE];
                int file_len = 0;
                // 명령어 메시지 수신
                memset(&msg_in, 0, sizeof(APP_MSG));
                memset(&msg_out, 0, sizeof(APP_MSG));
                readn(clnt_sock, &msg_in, sizeof(APP_MSG));
                msg_in.type = ntohl(msg_in.type);
                msg_type = msg_in.type;

                // 명령어에 따라 동작
                switch (msg_type)
                {
                case UP: //실행파일, C파일이 존재하는 폴더에 있는 파일만 업로드 가능
                    for (int i = down_dir_len; i < sizeof(down_dir); i++)
                        down_dir[i] = 0;
                    readn(clnt_sock, hash1, sizeof(hash1)); // 클라이언트에서 입력한 저장할 파일이름 수신
                    msg_in.msg_len = ntohl(msg_in.msg_len);
                    ciphertext_len = _decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char *)file_name2);
                    M_SHA256(file_name2, strlen(file_name2), hash2);
                    // 태그 체크
                    if (!strcmp(hash1, hash2))
                    {
                        printf("not hash\n");
                        break;
                    }
                    save_name = (char*)calloc(ciphertext_len, 1);
                    
                    for (int i = 0; i < ciphertext_len; i++)
                        save_name[i] = file_name2[i];

                    len = strlen(down_dir);
                    for (int i = 0; i < len; i++)
                        down_dir[len+i] = save_name[i];

                    // 클라이언트가 원하는 파일이름으로 생성
                    fd = open(down_dir, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
                    if (fd == -1)
                    {
                        //! error_handling("open() error");
                        printf("open() error\n");
                        break;
                    }
                    // 전송된 파일의 내용 수신
                    while (1)
                    {
                        memset(&msg_in, 0, sizeof(APP_MSG));
                        readn(clnt_sock, &msg_in, sizeof(APP_MSG));
                        msg_in.msg_len = ntohl(msg_in.msg_len);
                        msg_in.type = ntohl(msg_in.type);
                        if (msg_in.type == EOF | msg_in.type == 0) // 파일의 끝일때 종료
                        {
                            break;
                        }
                        if (msg_in.type == FILE_DATA) // 파일의 내용 전송일때만 동작
                        {
                            readn(clnt_sock, hash1, sizeof(hash1));
                            file_len = _decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)buf);
                            M_SHA256(buf, strlen(buf), hash2);
                            // 태그 체크
                            if (!strcmp(hash1, hash2))
                            {
                                printf("not hash\n");
                                break;
                            }
                            writen(fd, buf, file_len);
                        }
                        else if (msg_in.type == SEND_FINISH) // 전송이 끝났다는 메시지 클라이언트로 전송
                        {
                            free(save_name);
                            close(fd);
                            printf("Upload Success\n");
                            msg_type = WAIT;
                            break;
                        }
                        
                    }       
                    break;
                case DOWN: // 서버의 파일을 클라이언트가 다운로드, 실행파일, C파일이 존재하는 폴더에 있는 파일만 다운로드 가능
                    for (int i = down_dir_len; i < sizeof(down_dir); i++)
                        down_dir[i] = 0;
                    memset(file_name1, 0, sizeof(file_name1));
                    memset(hash1, 0, sizeof(hash1));
                    // 클라이언트가 다운로드 받고 싶은 파일 이름 수신
                    readn(clnt_sock, hash1, sizeof(hash1));
                    msg_in.msg_len = ntohl(msg_in.msg_len);
                    ciphertext_len = _decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char *)file_name1);

                    // 태그 체크
                    M_SHA256(file_name1, strlen(file_name1), hash2);
                    if (!strcmp(hash1, hash2))
                    {
                        printf("not hash\n");
                        break;
                    }
                    // 전송받은 파일 이름 저장
                    save_name = (char*)calloc(ciphertext_len, 1);
                    // save_name = (char*)calloc(ciphertext_len, sizeof(char));

                    for (int i = 0; i < ciphertext_len; i++)
                        save_name[i] = file_name1[i];

                    // for (int i = 0; i < ciphertext_len; i++)
                    //     printf("%c", save_name[i]);

                    len = strlen(down_dir);
                    for (int i = 0; i < len; i++)
                        down_dir[len+i] = save_name[i];

                    // 파일 존재 여부 확인
                    fd = open(down_dir, O_RDONLY, S_IRWXU);
                    // if (fd == -1) // 존재하지 않을 경우 파일이 없다는 메시지 전송
                    if (fd < 0)
                    {
                        //! error_handling("open() error");
                        printf("open() error\n");
                        memset(&msg_out, 0, sizeof(APP_MSG));
                        msg_out.type = htonl(NONE_FILE);
                        writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                        break;
                    }
                    else // 파일 존재 메시지 전송
                    {
                        memset(&msg_out, 0, sizeof(APP_MSG));
                        msg_out.type = htonl(EX_FILE);
                        writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                    }
 
                    // 파일 내용 보내기
                    while (1)
                    {
                        memset(buf, 0x00, BUFSIZE);
                        memset(hash1, 0, sizeof(hash1));
                        memset(&msg_out, 0, sizeof(APP_MSG));
                        file_len = readn(fd, buf, BUFSIZE); // 파일의 내용 부분적으로 반복 전송 만약 블록의 길이가 0일때 끝남
                        if (file_len == 0)
                        {
                            printf("finish file\n");
                            break;
                        }
                        // 암호화, 태그 생성 후 전성
                        M_SHA256(buf, BUFSIZE, hash1);
                        file_len = _encrypt((unsigned char *)buf, file_len, key, iv, msg_out.payload);
                        msg_out.msg_len = htonl(file_len);
                        msg_out.type = htonl(FILE_DATA);
                        writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                        writen(clnt_sock, hash1, sizeof(hash1));
                    }
                    // 전송할 내용이 없을때 끝냄
                    memset(&msg_out, 0, sizeof(APP_MSG));
                    msg_out.type = htonl(SEND_FINISH);
                    writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                    free(save_name);
                    close(fd);
                    msg_type = WAIT;
                    break;
                case LIST:
                    dir = opendir("./serversavedata/"); // 폴더의 파일 리스트 전송
                    if (dir != NULL)
                    {
                        // 여러개의 파일을 하나씩 읽어 암호화, 태그 생성 후 전송
                        while (1)
                        {
                            if (((ent = readdir(dir)) == NULL))
                            {
                                msg_type = SEND_FINISH;
                                msg_out.type = SEND_FINISH;
                                msg_out.type = htonl(msg_out.type);
                                writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                                break;
                            }
                            memset(file_name, 0, sizeof(file_name));
                            memcpy(file_name, ent->d_name, strlen(ent->d_name));
                            len = strlen(file_name);
                            memset(hash1, 0, sizeof(hash1));
                            M_SHA256(file_name, len, hash1);
                            len = _encrypt((unsigned char*)file_name, len, key, iv, msg_out.payload);
                            msg_out.type = SEND_LIST;
                            msg_out.msg_len = len;
                            msg_out.type = htonl(msg_out.type);
                            msg_out.msg_len = htonl(msg_out.msg_len);
                            writen(clnt_sock, &msg_out, sizeof(APP_MSG));
                            writen(clnt_sock, hash1, sizeof(hash1));
                        }
                        
                        closedir(dir);
                    }
                    else
                    {
                        return EXIT_FAILURE;
                    }

                    // 리스트 전송 끝
                    printf("finish\n");
                    // 대기 상태
                    msg_type = WAIT;
                    break;
                case QUIT:
                    msg_type = QUIT;
                    break;
                default:
                    break;
                }
            }
            close(clnt_sock); // QUIT 했으므로 더이상 클라이언트 종료이므로 없애기
            puts("Client disconnected...");
        }
        else // parent process
        {
            close(clnt_sock); // 역할 분담 클라이언드 소켓 사용할 필요없음
        }
    }
    close(serv_sock);

err:
    close(serv_sock);

    return 0;
}

static int _pad_unknopwn(void)
{
    unsigned long l;

    while ((l = ERR_get_error()) != 0)
    {
        if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
            return (1);    
    }
    return (0);
}

int rsaes_generator()
{
    int ret = 1;
    RSA *rsa; // rsa 구조체 포인터
    int num;
    BIO *bp_public = NULL, *bp_private = NULL; // BIO : 파일 포인터 역할, 생성한 공개키 쌍을 좀더 편리하게 파일 형태로 저장하기 위해 openssl에서 제공하는 유틸리티
    unsigned long e_value = RSA_F4;
    BIGNUM *exponent_e = BN_new(); // 큰 정수 라이브러리, 자료형

    rsa = RSA_new(); // rsa 구조체 공간 할당

    BN_set_word(exponent_e, e_value); // exponent_e bignum 자료형에 e_value 를 큰정수 형태로 만들어 놓는것 , 큰정수 구조체에  값을 설정하는

    if (RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == '\0') // 2048 비트짜리 키 생성 빅넘버 구조체에 넣는다 // 키 쌍 생성
    {
        fprintf(stderr, "RSA_generate_key_ex() error\n");
    }

    bp_public = BIO_new_file("./serversavedata/public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa); // 공개키 저장

    if (ret != 1)
    {
        goto err;
    }

    bp_private = BIO_new_file("./serversavedata/private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL); // 비밀키 저장

    if (ret != 1)
    {
        goto err;
    }

err:
    // 자원 반납
    RSA_free(rsa);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);

    return ret;
}

// ID/PW 확인 함수
int check_user(char *id, char *pw)
{
    FILE *fp = fopen("./serversavedata/user.txt", "r");
    char buf[IDPW_SIZE] = {0,};
    char *idpw_buf = NULL;
    int n = 0;

    while (1)
    {
        memset(buf, 0, IDPW_SIZE);
        fgets(buf, sizeof(buf), fp);
        if (buf[0] == 0)
        {
            n = 0;
            break;
        }
        idpw_buf = strtok(buf, " : ");

        if (strcmp(id, idpw_buf) == 0)
        {
            idpw_buf = strtok(NULL, " : ");
            idpw_buf = strtok(idpw_buf, "\n");

            if (strcmp(pw, idpw_buf) == 0)
            {
                n = 1;
                break;
            }
            else
            {
                n = 0;
            }
        }
        else
        {
            n = 0;
        }
    }
    return n;
}

// ID/PW 등록 함수
void enrollment_user(char *id, char *pw)
{
    FILE *fp = fopen("./serversavedata/user.txt", "a+");
    
    fprintf(fp, "%s", id);
    fprintf(fp, " : ");
    fprintf(fp, "%s", pw);
    fprintf(fp, "\n");
    
    fclose(fp);
    
}
void read_childproc(int sig) // 운영체제가 직접적으로 자식프로세스가 종료됬을때 호출해준다.
{
    pid_t pid;
    int status;
    pid = waitpid(-1, &status, WNOHANG); // 운영체제가 유지하고 있는 자식프로세스에 대한 정보를 가지고 온다.
    printf("removed proc id : %d\n", pid);
}