#include <stdio.h>
#include <string.h>
#include "base32.h"

int main(int argc, char **argv)
{
    int ret;
    char encodeBuffer[1024];
    unsigned char decodeBuffer[1024];
    unsigned int retLen;
    const char *src = "+651escehdgssfeS";

    printf("%u : %u\n", 20, Base32GetEncodeBufferLen(20));

    printf("src:%s\n", src);
    ret = Base32Encode(src, strlen(src), encodeBuffer, sizeof(encodeBuffer), &retLen);
    if (0 == ret)
    {
        printf("encode:%s\n", encodeBuffer);
    }
    ret = Base32Decode(encodeBuffer, decodeBuffer, sizeof(decodeBuffer), &retLen);
    if (0 == ret)
    {
        decodeBuffer[retLen] = '\0';
        printf("decode:%s\n", decodeBuffer);
    }
    getchar();
    return 0;
}