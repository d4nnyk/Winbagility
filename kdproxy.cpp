#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "utils.h"
#include "kd.h"


HANDLE proxyDBGPipe; //Windbg->Proxy
HANDLE proxyVMPipe; //Proxy->VM
UINT8 proxyRunning;
HANDLE ghMutex;


//Aka VM->Windbg
DWORD WINAPI server2client(LPVOID lpParam) {
	kd_packet_t* tmpKDPkt = (kd_packet_t*)malloc(65 * 1024);
	while (proxyRunning == 1){
		ReadKDPipe(proxyVMPipe, tmpKDPkt);
		DWORD numBytesWritten = WriteKDPipe(proxyDBGPipe, tmpKDPkt);
		WaitForSingleObject(ghMutex, INFINITE);
		printf("[VM->Windbg] Write to Windbg : %d\n", numBytesWritten);
		ParseKDPkt(tmpKDPkt);
		ReleaseMutex(ghMutex);
		//TODO: free tmpKDPkt
	}
	return 0;
}

//Aka Windbg->VM
DWORD WINAPI client2server(LPVOID lpParam) {

	kd_packet_t* tmpKDPkt = (kd_packet_t*)malloc(65 * 1024);
	BOOL result;
	while (proxyRunning == 1){
		DWORD numBytesRead = 0;
		DWORD numBytesWritten = 0;
		result = ReadKDPipe(proxyDBGPipe, tmpKDPkt);
		if (result == FASTBREAK_PKT){ //TODO: return fast-break !
			char endOfData = 0x62; //Define fast-break !
			printf("[BREAK]\n");
			WriteFile(proxyVMPipe, &endOfData, 1, &numBytesWritten, NULL);
			FlushFileBuffers(proxyVMPipe);
		}else{
			numBytesWritten = WriteKDPipe(proxyVMPipe, tmpKDPkt);
			WaitForSingleObject(ghMutex, INFINITE);
			printf("[Windbg->VM] Write to VM : %d\n", numBytesWritten);
			ParseKDPkt(tmpKDPkt);
			ReleaseMutex(ghMutex);
		}

	}
	return 0;
}



BOOL startKDProxy(){
	printf("Start KD Proxy...\n");
	OpenNamedPipe(&proxyVMPipe, "\\\\.\\pipe\\server");
	CreateNamedPipe(&proxyDBGPipe,"\\\\.\\pipe\\client");


	Sleep(100);
	proxyRunning = 1;

	CreateThread(NULL, 0, server2client, NULL, 0, NULL);
	CreateThread(NULL, 0, client2server, NULL, 0, NULL);

	while (1){
		Sleep(1000);
	}
}