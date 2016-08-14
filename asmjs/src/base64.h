#ifndef BASE64_H
#define BASE64_H

char* base64(const void* binaryData, int len, unsigned int *flen);
unsigned char* unbase64(const char* ascii, int len, unsigned int *flen);
#endif