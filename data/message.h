#ifndef USE_OPENSSL_MESSAGE_H
#define USE_OPENSSL_MESSAGE_H

#pragma pack(1)

/**
 * @brief 消息头
 */
struct message_head
{
    char signature[512];    ///< 签名
    int length;             ///< 数据包长度
};

/**
 * @brief 包头
 */
struct package_head
{
    int type;               ///< 包类型
    int crc32;              ///< 包 crc32 值
};

#pragma pack()

#endif //USE_OPENSSL_MESSAGE_H
