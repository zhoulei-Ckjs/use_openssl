#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "message.h"
#include "common.h"

#define SERV_PORT 9000      //连接到服务器端口

int main(int argc, char * const *argv)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);   //创建客户端socket

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    /*设置要连接的服务器信息*/
    serv_addr.sin_family = AF_INET;         //选择协议簇为IPV4
    serv_addr.sin_port = htons(SERV_PORT);  //连接到服务器端口

    /*这里为了方便，服务器地址固定写*/
    if(inet_pton(AF_INET, "192.168.6.128", &serv_addr.sin_addr) <= 0)     //ip地址转换，把第二个参数对应的Ip地址
    {
        printf("调用inet_pton失败！");
        exit(1);
    }

    /*连接到服务器*/
    if(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        char *perrorinfo = strerror(errno);
        printf("调用connect失败，错误码为：%d，错误信息为%s;\n", errno, perrorinfo);
        exit(1);
    }

    /// 包头
    char pcontent[1024];
    struct package_head p_head;
    p_head.crc32 = 999;
    p_head.type = 666;
    memcpy(pcontent, &p_head, sizeof(package_head));

    OSSL_LIB_CTX *libctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    /// 对包头进行签名
    if (sign(libctx, &sig, &sig_len, pcontent, sizeof(p_head)) == 0)
        goto end;

    printf("signature length=%d\n", sig_len);
    printf("sign Success\n");

    /// 消息头
    struct message_head m_head;
    m_head.length = sizeof(package_head);
    memcpy(m_head.signature, sig, sig_len);
    memcpy(pcontent, &m_head, sizeof(message_head));
    /// 发送消息头
    write(sockfd, pcontent, sizeof(message_head));
    printf("发送消息头：\n{\n\thead.signature=\n%s\n\thead.length=%d\n}\n", m_head.signature, m_head.length);

    /// 发送包头
    memcpy(pcontent, &p_head, sizeof(package_head));
    write(sockfd, pcontent, sizeof(package_head));
    printf("send package_head:\n{\n\tp_head.type=%d\n\tp_head.crc32=%d\n}\n", p_head.type, p_head.crc32);
    close(sockfd);

    printf("程序完毕，退出！");
    
end:
    OPENSSL_free(sig);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
