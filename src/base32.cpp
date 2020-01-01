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
    //��װmask
    for (unsigned int i = 0; i < availBitCount; i++)
    {
        mask |= (1 << i);
    }
    //ȡ��ǰ�ֽ�ʣ��λ
    value = ((*data) & mask);
    usedBitCount = SECTION_BITS_COUNT - availBitCount;
    value <<= usedBitCount;
    return value;
}

//************************************
// FullName:  inner_retriveSection
// Description: ��ȡ���һ/�����ֽڵ���λ������ֽ�
// Returns:   unsigned char �� ����Ϊ���һ/�����ֽ���λ��ɵ��ֽ�(����λ��Ч)
// Parameter: unsigned char *  & data����ǰ�ֽ�
// Parameter: unsigned int & usedBitCount����ǰ�ֽ��Ѿ�ʹ�õ�λ��(�Ӹ�λ����λ)
//************************************
static unsigned char inner_retriveSection(unsigned char * &data, unsigned int &usedBitCount)
{
    unsigned char value = 0;
    unsigned char mask = 0;
    unsigned int availBitCount;
    
    assert(NULL != data && (usedBitCount >= 0 && usedBitCount < 8));

    availBitCount = 8 - usedBitCount;//��ǰ�ֽڿ���λ��
    if (availBitCount < SECTION_BITS_COUNT)//����λ��С��SECTION_BITS_COUNTʱ������Ҫ����һ���ֽ�ȡλ
    {
        //��װmask
        for (unsigned int i = 0; i < availBitCount; i++)
        {
            mask |= (1 << i);
        }
        //ȡ��ǰ�ֽ�ʣ��λ
        value = ((*data) & mask);

        usedBitCount = SECTION_BITS_COUNT - availBitCount;//����ռ����һ���ֽڵ�λ��
        value <<= usedBitCount;
        //ȡ��һ���ֽ�
        ++data;
        availBitCount = 8 - usedBitCount;//��һ���ֽڻ����õ�λ��
        //��װmask
        mask = 0;
        for (unsigned int i = 0; i < usedBitCount; i++)
        {
            mask |= (1 << i);
        }
        value |= (((*data) >> availBitCount) & mask);
    }
    else//����λ�����ڵ���SECTION_BITS_COUNTʱ��ֻ��Ҫ�ڵ�ǰ�ֽڽ���ȡλ
    {
        availBitCount -= SECTION_BITS_COUNT;//ʣ�¿���λ��
        value = (((*data) >> availBitCount) & 0x1F);
        if (0 == availBitCount)//��ǰ�ֽ��޿���λ
        {
            //��ת����һ���ֽ�
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
// Description: ���ݸ�����Ҫ���ܵ����ݳ��ȼ�������Ҫ�Ļ��泤��
// Returns:   unsigned int ���ؼ�������Ļ��泤��
// Parameter: unsigned int dataLen: ��Ҫ���ܵ����ݳ���
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
        //���ص�����������0��MAX_MAP_CHAR_COUNT֮��
        //usedBitCountһ��С��SECTION_BITS_COUNT
        //pByteֻ�ܴ���[data, data+dataLen]֮��
        assert(index >= 0 && index < MAX_MAP_CHAR_COUNT
            && usedBitCount < 8
            && pByte <= (((unsigned char *)data) + dataLen));
        buffer[i] = g_mapChars[index];
    }
    //�����������usedBitCount��Ϊ0ʱ���������⴦�����һ���ֽڵĺ�λ
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
// Description: ʹ��Base32��������
// Returns:   int �ɹ�����0�����򷵻ش���
// Parameter: const void * data����Ҫ���ܵ�����
// Parameter: unsigned int dataLen�� ��Ҫ���ܵ��ֽ���
// Parameter: unsigned char * buffer����ż��ܺ�Ļ����ַ
// Parameter: unsigned int bufLen����ż��ܺ�Ļ����С
// Parameter: unsigned int * pRetLen�����ؼ��ܺ�ĳ���(����ΪNULL)
// Comment:
//          ����ENOMEM�������С������pRetLen��������Ҫ�ĳ���
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

//dataLen(������������'\0')
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
        if (needBitCount > availBitCount)//��Ҫ��λ�����ڿ���λ��
        {
            bitCnt = availBitCount;
            needBitCount -= availBitCount;
        }
        else//��Ҫ��λ��С�ڵ��ڿ���λ��
        {
            bitCnt = needBitCount;
            needBitCount = 0;
        }
        usedBitCount += bitCnt;
        byte |= (inner_getBitsOfByte(value, offset, bitCnt) << needBitCount);
        //��Ҫ��λ������0ʱ����Ҫת����һ���ַ�
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
