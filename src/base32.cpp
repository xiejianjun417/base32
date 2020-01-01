#include <assert.h>
#include <errno.h>
#include <string.h>
#include "base32.h"

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

#define SECTION_BITS_COUNT      5
#define ENCRYPT_MAP_CHAR        "ABCDEFGHIJKLMNOPQRSTUVWXYZ345678"
#define MAX_MAP_CHAR_COUNT      (sizeof(ENCRYPT_MAP_CHAR) - 1)

static const char * const g_mapChars = ENCRYPT_MAP_CHAR;

static unsigned char inner_makeupLastSection(unsigned char *data, unsigned int usedBitCount)
{
    unsigned char value = 0;
    unsigned char mask = 0;
    unsigned int availBitCount;

    assert(NULL != data && usedBitCount > 0 && usedBitCount <= 8);
    availBitCount = 8 - usedBitCount;
    //组装mask
    for (unsigned int i = 0; i < availBitCount; i++)
    {
        mask |= (1 << i);
    }
    //取当前字节剩余位
    value = ((*data) & mask);
    usedBitCount = SECTION_BITS_COUNT - availBitCount;
    value <<= usedBitCount;
    return value;
}

//************************************
// FullName:  inner_retriveSection
// Description: 获取最近一/两个字节的五位组成新字节
// Returns:   unsigned char ： 返回为最近一/两个字节五位组成的字节(后五位有效)
// Parameter: unsigned char *  & data：当前字节
// Parameter: unsigned int & usedBitCount：当前字节已经使用的位数(从高位到低位)
//************************************
static unsigned char inner_retriveSection(unsigned char * &data, unsigned int &usedBitCount)
{
    unsigned char value = 0;
    unsigned char mask = 0;
    unsigned int availBitCount;
    
    assert(NULL != data && (usedBitCount >= 0 && usedBitCount < 8));

    availBitCount = 8 - usedBitCount;//当前字节可用位数
    if (availBitCount < SECTION_BITS_COUNT)//可用位数小于SECTION_BITS_COUNT时，还需要在下一个字节取位
    {
        //组装mask
        for (unsigned int i = 0; i < availBitCount; i++)
        {
            mask |= (1 << i);
        }
        //取当前字节剩余位
        value = ((*data) & mask);

        usedBitCount = SECTION_BITS_COUNT - availBitCount;//计算占用下一个字节的位数
        value <<= usedBitCount;
        //取下一个字节
        ++data;
        availBitCount = 8 - usedBitCount;//下一个字节还可用的位数
        //组装mask
        mask = 0;
        for (unsigned int i = 0; i < usedBitCount; i++)
        {
            mask |= (1 << i);
        }
        value |= (((*data) >> availBitCount) & mask);
    }
    else//可用位数大于等于SECTION_BITS_COUNT时，只需要在当前字节进行取位
    {
        availBitCount -= SECTION_BITS_COUNT;//剩下可用位数
        value = (((*data) >> availBitCount) & 0x1F);
        if (0 == availBitCount)//当前字节无可用位
        {
            //跳转到下一个字节
            ++data;
            usedBitCount = 0;
        }
        else
        {
            usedBitCount += SECTION_BITS_COUNT;
        }
    }
    return value;
}

//************************************
// FullName:  Base32GetEncodeBufferLen
// Description: 根据给定需要加密的数据长度计算所需要的缓存长度
// Returns:   unsigned int 返回加密所需的缓存长度
// Parameter: unsigned int dataLen: 需要加密的数据长度
//************************************
unsigned int Base32GetEncodeBufferLen(unsigned int dataLen)
{
    dataLen <<= 3;
    return dataLen / SECTION_BITS_COUNT + ((0 != (dataLen % SECTION_BITS_COUNT)) ? 1 : 0) + 1;
}

static unsigned int inner_base32Encode(const void *data, unsigned int dataLen, unsigned char *buffer)
{
    unsigned char *pByte;
    unsigned int sectionCount;
    unsigned int usedBitCount;
    unsigned char index;

    assert(NULL != data && 0 != dataLen && NULL != buffer);

    pByte = (unsigned char *)data;
    sectionCount = (dataLen << 3)/ SECTION_BITS_COUNT;
    usedBitCount = 0;
    for (unsigned int i = 0; i < sectionCount; i++)
    {
        index = inner_retriveSection(pByte, usedBitCount);
        //返回的索引必须在0到MAX_MAP_CHAR_COUNT之间
        //usedBitCount一定小于SECTION_BITS_COUNT
        //pByte只能处于[data, data+dataLen]之间
        assert(index >= 0 && index < MAX_MAP_CHAR_COUNT
            && usedBitCount < 8
            && pByte <= (((unsigned char *)data) + dataLen));
        buffer[i] = g_mapChars[index];
    }
    //若遍历到最后，usedBitCount不为0时，代表特殊处理最后一个字节的后几位
    if (0 != usedBitCount)
    {
        index = inner_makeupLastSection(pByte, usedBitCount);
        assert(index >= 0 && index < MAX_MAP_CHAR_COUNT);
        buffer[sectionCount] = g_mapChars[index];
        ++sectionCount;
    }
    buffer[sectionCount] = '\0';
    ++sectionCount;
    return sectionCount;
}

//************************************
// Function:  Base32Encode
// Description: 使用Base32加密数据
// Returns:   int 成功返回0，否则返回错误
// Parameter: const void * data：需要加密的数据
// Parameter: unsigned int dataLen： 需要加密的字节数
// Parameter: unsigned char * buffer：存放加密后的缓存地址
// Parameter: unsigned int bufLen：存放加密后的缓存大小
// Parameter: unsigned int * pRetLen：返回加密后的长度(不能为NULL)
// Comment:
//          返回ENOMEM代表缓存大小不够，pRetLen将返回需要的长度
//************************************
int Base32Encode(const void *data, unsigned int dataLen, void *buffer, unsigned int bufLen, unsigned int *pRetLen)
{
    unsigned int len;

    if (NULL == data || 0 == dataLen || NULL == buffer || 0 == bufLen || NULL == pRetLen)
    {
        return EINVAL;
    }
    len = Base32GetEncodeBufferLen(dataLen);
    if (bufLen < len)
    {
        *pRetLen = len;
        return ENOMEM;
    }
    *pRetLen = inner_base32Encode(data, dataLen, (unsigned char *)buffer);
    return 0;
}

//dataLen(不包含结束符'\0')
unsigned int Base32GetDecodeBufferLen(unsigned int dataLen)
{
    return (dataLen * SECTION_BITS_COUNT) >> 3;
}

unsigned char inner_indexOfChar(unsigned char ch)
{
    for (unsigned char i = 0; i < MAX_MAP_CHAR_COUNT; i++)
    {
        if (g_mapChars[i] == ch)
        {
            return i;
        }
    }
    return (unsigned char)-1;
}

static inline unsigned char inner_getBitsOfByte(unsigned char ch, unsigned int offset, unsigned int count)
{
    unsigned char mask = 0;

    assert(offset + count <= SECTION_BITS_COUNT);

    for (unsigned int i = 0; i < count; i++)
    {
        mask |= (1 << i);
    }
    offset = SECTION_BITS_COUNT - offset - count;
    return (ch >> offset) & mask;
}

static int inner_makeupByte(const unsigned char *&data, unsigned char &value, unsigned int &usedBitCount, unsigned char &byte)
{
    unsigned int availBitCount;
    unsigned int needBitCount = 8;
    unsigned int bitCnt;
    unsigned int offset;

    byte = '\0';
    availBitCount = SECTION_BITS_COUNT - usedBitCount;
    while (needBitCount > 0)
    {
        if ((unsigned char)-1 == value)
        {
            value = inner_indexOfChar(*data);
            if ((unsigned char)-1 == value)
            {
                return EIO;
            }
            usedBitCount = 0;
            availBitCount = SECTION_BITS_COUNT;
        }
        offset = usedBitCount;
        if (needBitCount > availBitCount)//需要的位数大于可用位数
        {
            bitCnt = availBitCount;
            needBitCount -= availBitCount;
        }
        else//需要的位数小于等于可用位数
        {
            bitCnt = needBitCount;
            needBitCount = 0;
        }
        usedBitCount += bitCnt;
        byte |= (inner_getBitsOfByte(value, offset, bitCnt) << needBitCount);
        //需要的位数大于0时，需要转换下一个字符
        if (needBitCount > 0)
        {
            value = (unsigned char)-1;
            ++data;
        }
    }
    return 0;
}

static int inner_base32Decode(const char *data, unsigned int dataLen, void *buffer, unsigned int bufLen, unsigned int *pRetLen)
{
    int ret = 0;
    unsigned char value = (unsigned char)-1;
    unsigned int usedBitCount = 0;
    unsigned char *pByte;
    unsigned int count;
    const unsigned char *pString;

    *pRetLen = 0;
    pByte = (unsigned char *)buffer;
    pString = (const unsigned char *)data;
    count = Base32GetDecodeBufferLen(dataLen);
    if (bufLen < count)
    {
        *pRetLen = count;
        return ENOMEM;
    }
    for (unsigned int i = 0; i < count; i++)
    {
        ret = inner_makeupByte(pString, value, usedBitCount, pByte[i]);
        if (0 != ret)
        {
            break;
        }
    }
    if (0 == ret)
    {
        *pRetLen = count;
    }
    return ret;
}

int Base32Decode(const char *pEncodeString, void *buffer, unsigned int bufLen, unsigned int *pRetLen)
{
    if (NULL == pEncodeString || NULL == buffer || 0 == bufLen || NULL == pRetLen)
    {
        return EINVAL;
    }
    if ('\0' == *pEncodeString)
    {
        *pRetLen = 0;
        return 0;
    }
    return inner_base32Decode(pEncodeString, (unsigned int)strlen(pEncodeString), buffer, bufLen, pRetLen);
}

#ifdef __cplusplus
}
#endif//__cplusplus
