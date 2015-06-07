#ifndef __UTILS_H__
#define __UTILS_H__

int roundup16(int value);
void dumpHexData(char *tmp, int len);
void printHexData(char *tmp, int len);

BOOL CreateNamedPipe(HANDLE *hPipe, char *pipeName);
BOOL OpenNamedPipe(HANDLE *hPipe, char *pipeName);
uint8_t Get8Pipe(HANDLE hPipe);
uint16_t Get16Pipe(HANDLE hPipe);
uint32_t Get32Pipe(HANDLE hPipe);
uint64_t Get64Pipe(HANDLE hPipe);
DWORD PutPipe(HANDLE hPipe, uint8_t *data, uint64_t size);
DWORD Put8Pipe(HANDLE hPipe, uint8_t data);
DWORD Put32Pipe(HANDLE hPipe, uint8_t data);
DWORD Put64Pipe(HANDLE hPipe, uint64_t data);

#endif //__UTILS_H__