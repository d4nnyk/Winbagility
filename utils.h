#ifndef __UTILS_H__
#define __UTILS_H__

int roundup16(int value);
void dumpHexData(char *tmp, int len);
void printHexData(char *tmp, int len);

UINT8 Get8Pipe(HANDLE hPipe);
UINT16 Get16Pipe(HANDLE hPipe);
UINT32 Get32Pipe(HANDLE hPipe);

BOOL CreateDBGNamedPipe(HANDLE *hPipe);
BOOL OpenVMNamedPipe(HANDLE *hPipe);

#endif //__UTILS_H__