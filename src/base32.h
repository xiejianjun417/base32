#ifndef _BASE32_H_
#define _BASE32_H_

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

//************************************
// Function:  Base32GetEncodeBufferLen
// Description: ���ݸ�����Ҫ���ܵ����ݳ��ȼ�������Ҫ�Ļ��泤��
// Returns:   unsigned int ���ؼ�������Ļ��泤��
// Parameter: unsigned int dataLen: ��Ҫ���ܵ����ݳ���
//************************************
unsigned int Base32GetEncodeBufferLen(unsigned int dataLen);

//************************************
// Function:  Base32GetDecodeBufferLen
// Description: ���ݸ�����Ҫ���ܵ����ݳ��ȼ�������Ҫ�Ļ��泤��
// Returns:   unsigned int ���ؽ�������Ļ��泤��
// Parameter: unsigned int dataLen: ��Ҫ���ܵ����ݳ���(������'\0');
// Comment:
//************************************
unsigned int Base32GetDecodeBufferLen(unsigned int dataLen);

//************************************
// Function:  Base32Encode
// Description: ��������
// Returns:   int �ɹ�����0�����򷵻ش���
// Parameter: const void * data����Ҫ���ܵ�����
// Parameter: unsigned int dataLen�� ��Ҫ���ܵ��ֽ���
// Parameter: void* buffer����ż��ܺ�Ļ����ַ
// Parameter: unsigned int bufLen����ż��ܺ�Ļ����С
// Parameter: unsigned int * pRetLen�����ؼ��ܺ�ĳ���(����ΪNULL)
// Comment:
//          ����ENOMEM�������С������pRetLen��������Ҫ�ĳ���
//************************************
int Base32Encode(const void *data, unsigned int dataLen, void *buffer, unsigned int bufLen, unsigned int *pRetLen);

//************************************
// Function:  Base32Decode
// Description: ����Base32�����ַ���
// Returns:   int �ɹ�����0�����򷵻ش���
// Parameter: const char * pEncodeString����Ҫ���ܵ��ַ���
// Parameter: void * buffer����Ž��ܺ�Ļ����ַ
// Parameter: unsigned int bufLen����Ž��ܺ�Ļ����С
// Parameter: unsigned int * pRetLen�����ؽ��ܺ�ĳ���(����ΪNULL)
// Comment:
//          ����ENOMEM�������С������pRetLen��������Ҫ�ĳ���
//************************************
int Base32Decode(const char *pEncodeString, void *buffer, unsigned int bufLen, unsigned int *pRetLen);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//_BASE32_H_
