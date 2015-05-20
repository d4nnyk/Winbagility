#include "stdafx.h"
#include "windows.h"

//TODO: macro
int roundup16(int value){
	return (value + 15) & ~15;
}

void dumpHexData(char *tmp, int len){
	printf("char pkt[] = {\n");
	int i;
	for (i = 0; i<len; i++){
		printf("0x%02x, ", tmp[i] & 0xFF);
		if (i % 16 == 15){
			printf("\n");
		}
	}
	if (i % 16 != 0){
		printf("\n");
	}
	printf("};");
}

void printHexData(char *tmp, int len){
	int i;
	for (i = 0; i<len; i++){
		printf("%02x ", tmp[i] & 0xFF);
		if (i % 16 == 15){
			printf("\n");
		}
	}
	if (i % 16 != 0){
		printf("\n");
	}
}



UINT8 Get8Pipe(HANDLE hPipe){
	UINT8 tmp;
	DWORD avalaibleBytes;
	while (1){
		PeekNamedPipe(hPipe, NULL, 0, NULL, &avalaibleBytes, NULL);
		if (avalaibleBytes >= 1){
			DWORD numBytesRead = 0;
			BOOL result = ReadFile(hPipe, &tmp, 1, &numBytesRead, NULL);
			return tmp;
		}
		else{
			Sleep(10);
		}
	}
	return 0;
}

UINT16 Get16Pipe(HANDLE hPipe){
	UINT16 tmp;
	DWORD avalaibleBytes;
	while (1){
		PeekNamedPipe(hPipe, NULL, 0, NULL, &avalaibleBytes, NULL);
		if (avalaibleBytes >= 2){
			DWORD numBytesRead = 0;
			BOOL result = ReadFile(hPipe, &tmp, 2, &numBytesRead, NULL);
			return tmp;
		}
		else{
			Sleep(10);
		}
	}
	return 0;
}

UINT32 Get32Pipe(HANDLE hPipe){
	UINT32 tmp;
	DWORD avalaibleBytes;
	while (1){
		PeekNamedPipe(hPipe, NULL, 0, NULL, &avalaibleBytes, NULL);
		if (avalaibleBytes >= 4){
			DWORD numBytesRead = 0;
			BOOL result = ReadFile(hPipe, &tmp, 4, &numBytesRead, NULL);
			return tmp;
		}
		else{
			Sleep(10);
		}
	}
	return 0;
}


//Create Windbg->Proxy/Server Named Pipe
BOOL CreateDBGNamedPipe(HANDLE *hPipe){ //TODO: name argument
	*hPipe = CreateNamedPipe(
		L"\\\\.\\pipe\\client",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE,
		1,
		65 * 1024,
		65 * 1024,
		1000,
		NULL
		);
	if (*hPipe == NULL || *hPipe == INVALID_HANDLE_VALUE) {
		printf("Failed to create outbound pipe instance.\n");
		system("pause");
		return false;
	}
	printf("[Main] Client NamedPipe created ! Waiting Windbg to connect...\n");
	BOOL result = ConnectNamedPipe(*hPipe, NULL);
	if (!result) {
		printf("[Main] Failed to make connection on named pipe.\n");
		CloseHandle(*hPipe);
		system("pause");
		return false;
	}
	printf("[Main] Client connected !\n");
	return true;
}

BOOL OpenVMNamedPipe(HANDLE *hPipe){ //TODO: name argument
	while (1){
		*hPipe = CreateFile(
			L"\\\\.\\pipe\\server",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (*hPipe != INVALID_HANDLE_VALUE)
			break;

		if (GetLastError() != ERROR_PIPE_BUSY){
			printf("[Main] Waiting for server NamedPipe... \n");
			Sleep(1000);
		}
		else{
			if (!WaitNamedPipe(L"\\\\.\\pipe\\server", 1000)){
				printf("[Main] Error when wait NamedPipe\n");
			}
		}
	}
	DWORD dwMode = PIPE_TYPE_BYTE;
	BOOL result = SetNamedPipeHandleState(
		*hPipe,
		&dwMode,
		NULL,
		NULL);
	if (!result){
		system("pause");
		return false;
	}
	printf("[Main] Connected to server NamedPipe !\n");
	return true;
}