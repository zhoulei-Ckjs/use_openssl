#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "message.h"
#include "common.h"

#define SERV_PORT 9000

int main()
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERV_PORT);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int reuseaddr = 1;
    if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuseaddr, sizeof(reuseaddr)) == -1)
    {
        char *perrorinfo = strerror(errno);
        printf("setsockopt(SO_REUSEADDR)返回值为%d，错误码为：d%，错误信息为：%s；\n", -1, errno, perrorinfo);
    }

    int result = bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));   //绑定服务器地址结构体
    if(result == -1)
    {
        char *perrorinfo = strerror(errno);
        printf("bind返回值为%d，错误码为：%d，错误信息为%s;\n", -1, errno, perrorinfo);
        return -1;
    }
    listen(listen_fd, 32);   //参数2表示服务器可以积压未处理完的连入请求总数

    int connfd = -1;

    /// 签名后的数据
    char encrypted_body[1024];

    /// 包头
    struct package_head p_head;
    p_head.type = 1;
    p_head.crc32 = 2;

    char recvline[1024];
    for(;;)
    {
        /*等待客户端连接*/
        connfd = accept(listen_fd, (struct sockaddr*)NULL, NULL);
        //从已完成连接队列的队首取出一项（已完成TCP连接）
        //如果已完成连接队列是空的，那么accept会一直卡在这里，一直到队列中有一项时才被唤醒
        int n = read(connfd, recvline, sizeof(message_head));
        if(n > 0)
        {
            printf("接收字节：%d\n", n);
            message_head head;
            memcpy(&head, recvline, sizeof(message_head));
            printf("{\n\thead.signature=\n%s\n\thead.length=%d\n}\n", head.signature, head.length);

            memset(recvline, '\0', sizeof(recvline));
            n = read(connfd, recvline, head.length);

            /// 进行签名校验
            OSSL_LIB_CTX *libctx = NULL;
            if (verify(libctx, reinterpret_cast<const unsigned char*>(head.signature), 512, recvline, head.length) == 0)
                goto end;
            printf("verify success\n");

            if(n > 0)
            {
                printf("receive package_head:\n{\n\tp_head.type=%d\n\tp_head.crc32=%d\n}\n",
                       ((package_head*)recvline)->type,
                       ((package_head*)recvline)->crc32);
            }
            else
                printf("error: read returns negative!");
end:
//            OPENSSL_free(sig);
            OSSL_LIB_CTX_free(libctx);
        }
        else
            sleep(1);
    }
    close(listen_fd);

    return 0;
}