#ifndef _BASE32_H_
#define _BASE32_H_

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

//************************************
// Function:  Base32GetEncodeBufferLen
// Description: 根据给定需要加密的数据长度计算所需要的缓存长度
// Returns:   unsigned int 返回加密所需的缓存长度
// Parameter: unsigned int dataLen: 需要加密的数据长度
//************************************
unsigned int Base32GetEncodeBufferLen(unsigned int dataLen);

//************************************
// Function:  Base32GetDecodeBufferLen
// Description: 根据给定需要解密的数据长度计算所需要的缓存长度
// Returns:   unsigned int 返回解密所需的缓存长度
// Parameter: unsigned int dataLen: 需要加密的数据长度(不包含'\0');
// Comment:
//************************************
unsigned int Base32GetDecodeBufferLen(unsigned int dataLen);

//************************************
// Function:  Base32Encode
// Description: 加密数据
// Returns:   int 成功返回0，否则返回错误
// Parameter: const void * data：需要加密的数据
// Parameter: unsigned int dataLen： 需要加密的字节数
// Parameter: void* buffer：存放加密后的缓存地址
// Parameter: unsigned int bufLen：存放加密后的缓存大小
// Parameter: unsigned int * pRetLen：返回加密后的长度(不能为NULL)
// Comment:
//          返回ENOMEM代表缓存大小不够，pRetLen将返回需要的长度
//************************************
int Base32Encode(const void *data, unsigned int dataLen, void *buffer, unsigned int bufLen, unsigned int *pRetLen);

//************************************
// Function:  Base32Decode
// Description: 解密Base32加密字符串
// Returns:   int 成功返回0，否则返回错误
// Parameter: const char * pEncodeString：需要解密的字符串
// Parameter: void * buffer：存放解密后的缓存地址
// Parameter: unsigned int bufLen：存放解密后的缓存大小
// Parameter: unsigned int * pRetLen：返回解密后的长度(不能为NULL)
// Comment:
//          返回ENOMEM代表缓存大小不够，pRetLen将返回需要的长度
//************************************
int Base32Decode(const char *pEncodeString, void *buffer, unsigned int bufLen, unsigned int *pRetLen);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_BASE32_H_
