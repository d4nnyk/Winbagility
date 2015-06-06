/* $Id: DBGCTcp.cpp $ */
/** @file
 * DBGC - Debugger Console, TCP backend.
 */

/*
 * Copyright (C) 2006-2013 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 */


/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/
#include <VBox/dbg.h>
#include <VBox/vmm/cfgm.h>
#include <VBox/err.h>

#include <iprt/thread.h>
#include <iprt/tcp.h>
#include <VBox/log.h>
#include <iprt/assert.h>

#include <iprt/string.h>


/*******************************************************************************
*   Structures and Typedefs                                                    *
*******************************************************************************/
/**
 * Debug console TCP backend instance data.
 */
typedef struct DBGCTCP
{
    /** The I/O backend for the console. */
    DBGCBACK    Back;
    /** The socket of the connection. */
    RTSOCKET    Sock;
    /** Connection status. */
    bool        fAlive;
} DBGCTCP;
/** Pointer to the instance data of the console TCP backend. */
typedef DBGCTCP *PDBGCTCP;

/** Converts a pointer to DBGCTCP::Back to a pointer to DBGCTCP. */
#define DBGCTCP_BACK2DBGCTCP(pBack) ( (PDBGCTCP)((char *)pBack - RT_OFFSETOF(DBGCTCP, Back)) )


/*******************************************************************************
*   Internal Functions                                                         *
*******************************************************************************/
static int  dbgcTcpConnection(RTSOCKET Sock, void *pvUser);



/**
 * Checks if there is input.
 *
 * @returns true if there is input ready.
 * @returns false if there not input ready.
 * @param   pBack       Pointer to the backend structure supplied by
 *                      the backend. The backend can use this to find
 *                      it's instance data.
 * @param   cMillies    Number of milliseconds to wait on input data.
 */
static DECLCALLBACK(bool) dbgcTcpBackInput(PDBGCBACK pBack, uint32_t cMillies)
{
    PDBGCTCP pDbgcTcp = DBGCTCP_BACK2DBGCTCP(pBack);
    if (!pDbgcTcp->fAlive)
        return false;
    int rc = RTTcpSelectOne(pDbgcTcp->Sock, cMillies);
    if (RT_FAILURE(rc) && rc != VERR_TIMEOUT)
        pDbgcTcp->fAlive = false;
    return rc != VERR_TIMEOUT;
}


/**
 * Read input.
 *
 * @returns VBox status code.
 * @param   pBack       Pointer to the backend structure supplied by
 *                      the backend. The backend can use this to find
 *                      it's instance data.
 * @param   pvBuf       Where to put the bytes we read.
 * @param   cbBuf       Maximum nymber of bytes to read.
 * @param   pcbRead     Where to store the number of bytes actually read.
 *                      If NULL the entire buffer must be filled for a
 *                      successful return.
 */
static DECLCALLBACK(int) dbgcTcpBackRead(PDBGCBACK pBack, void *pvBuf, size_t cbBuf, size_t *pcbRead)
{
    PDBGCTCP pDbgcTcp = DBGCTCP_BACK2DBGCTCP(pBack);
    if (!pDbgcTcp->fAlive)
        return VERR_INVALID_HANDLE;
    int rc = RTTcpRead(pDbgcTcp->Sock, pvBuf, cbBuf, pcbRead);
    if (RT_FAILURE(rc))
        pDbgcTcp->fAlive = false;
    return rc;
}

/**
 * Write (output).
 *
 * @returns VBox status code.
 * @param   pBack       Pointer to the backend structure supplied by
 *                      the backend. The backend can use this to find
 *                      it's instance data.
 * @param   pvBuf       What to write.
 * @param   cbBuf       Number of bytes to write.
 * @param   pcbWritten  Where to store the number of bytes actually written.
 *                      If NULL the entire buffer must be successfully written.
 */
static DECLCALLBACK(int) dbgcTcpBackWrite(PDBGCBACK pBack, const void *pvBuf, size_t cbBuf, size_t *pcbWritten)
{
    PDBGCTCP pDbgcTcp = DBGCTCP_BACK2DBGCTCP(pBack);
    if (!pDbgcTcp->fAlive)
        return VERR_INVALID_HANDLE;

    /*
     * convert '\n' to '\r\n' while writing.
     */
    int     rc = 0;
    size_t  cbLeft = cbBuf;
    while (cbLeft)
    {
        size_t  cb = cbLeft;
        /* write newlines */
        if (*(const char *)pvBuf == '\n')
        {
            rc = RTTcpWrite(pDbgcTcp->Sock, "\n\r", 2);
            cb = 1;
        }
        /* write till next newline */
        else
        {
            const char *pszNL = (const char *)memchr(pvBuf, '\n', cbLeft);
            if (pszNL)
                cb = (uintptr_t)pszNL - (uintptr_t)pvBuf;
            rc = RTTcpWrite(pDbgcTcp->Sock, pvBuf, cb);
        }
        if (RT_FAILURE(rc))
        {
            pDbgcTcp->fAlive = false;
            break;
        }

        /* advance */
        cbLeft -= cb;
        pvBuf = (const char *)pvBuf + cb;
    }

    /*
     * Set returned value and return.
     */
    if (pcbWritten)
        *pcbWritten = cbBuf - cbLeft;
    return rc;
}

/** @copydoc FNDBGCBACKSETREADY */
static DECLCALLBACK(void) dbgcTcpBackSetReady(PDBGCBACK pBack, bool fBusy)
{
    /* stub */
    NOREF(pBack);
    NOREF(fBusy);
}


/**
 * Serve a TCP Server connection.
 *
 * @returns VBox status.
 * @returns VERR_TCP_SERVER_STOP to terminate the server loop forcing
 *          the RTTcpCreateServer() call to return.
 * @param   Sock        The socket which the client is connected to.
 *                      The call will close this socket.
 * @param   pvUser      The VM handle.
 */
static DECLCALLBACK(int) dbgcTcpConnection(RTSOCKET Sock, void *pvUser)
{
    LogFlow(("dbgcTcpConnection: connection! Sock=%d pvUser=%p\n", Sock, pvUser));

    /*
     * Start the console.
     */
    DBGCTCP    DbgcTcp;
    DbgcTcp.Back.pfnInput    = dbgcTcpBackInput;
    DbgcTcp.Back.pfnRead     = dbgcTcpBackRead;
    DbgcTcp.Back.pfnWrite    = dbgcTcpBackWrite;
    DbgcTcp.Back.pfnSetReady = dbgcTcpBackSetReady;
    DbgcTcp.fAlive = true;
    DbgcTcp.Sock   = Sock;
    int rc = DBGCCreate((PUVM)pvUser, &DbgcTcp.Back, 0);
    LogFlow(("dbgcTcpConnection: disconnect rc=%Rrc\n", rc));
    return rc;
}

#include <Windows.h>
#include <stdio.h>

BOOL CreateDBGNamedPipe(HANDLE *hPipe){ //TODO: name argument
	*hPipe = CreateNamedPipeA(
		"\\\\.\\pipe\\debugger",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE ,
		1,
		1 * 1024,
		1 * 1024,
		1000,
		NULL
		);
	if (*hPipe == NULL || *hPipe == INVALID_HANDLE_VALUE) {
		printf("Failed to create outbound pipe instance.\n");
		system("pause");
		return false;
	}
	printf("[Main] NamedPipe created ! Waiting connection...\n");
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
		*hPipe = CreateFileA(
			"\\\\.\\pipe\\debugger",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (*hPipe != INVALID_HANDLE_VALUE)
			break;

		if (GetLastError() != ERROR_PIPE_BUSY){
			printf("[Main] Waiting for NamedPipe... \n");
			Sleep(1000);
		}
		else{
			if (!WaitNamedPipeA("\\\\.\\pipe\\debugger", 1000)){
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

bool GetPipe(HANDLE hPipe, uint8_t* data, uint64_t size){
	DWORD avalaibleBytes;
	while (1){
		PeekNamedPipe(hPipe, NULL, 0, NULL, &avalaibleBytes, NULL);
		if (avalaibleBytes >= size){
			DWORD numBytesRead = 0;
			BOOL result = ReadFile(hPipe, data, size, &numBytesRead, NULL);
			return true;
		}
		else{
			Sleep(10);
		}
	}
	return false;
}

uint8_t Get8Pipe(HANDLE hPipe){
	uint8_t tmp;
	GetPipe(hPipe, &tmp, sizeof(tmp));
	return tmp;
}

uint32_t Get32Pipe(HANDLE hPipe){
	uint32_t tmp;
	GetPipe(hPipe, (uint8_t*)&tmp, sizeof(tmp));
	return tmp;
}

uint64_t Get64Pipe(HANDLE hPipe){
	uint64_t tmp;
	GetPipe(hPipe, (uint8_t*)&tmp, sizeof(tmp));
	return tmp;
}

DWORD PutPipe(HANDLE hPipe, uint8_t *data, uint64_t size){
	DWORD numBytesWritten = 0;
	BOOL result = WriteFile(hPipe, data, size, &numBytesWritten, NULL);
	return numBytesWritten;
}

DWORD Put8Pipe(HANDLE hPipe, uint8_t data){
	return PutPipe(hPipe, (uint8_t*)&data, sizeof(data));
}

DWORD Put32Pipe(HANDLE hPipe, uint32_t data){
	return PutPipe(hPipe, (uint8_t*)&data, sizeof(data));
}

DWORD Put64Pipe(HANDLE hPipe, uint64_t data){
	return PutPipe(hPipe, (uint8_t*)&data, sizeof(data));
}
enum{
	PHYSICAL_VIRTUAL,
	READ_PHYSICAL,
	READ_PHYSICAL_8,
	READ_PHYSICAL_32,
	READ_PHYSICAL_64,
	READ_REGISTER_64,
	GET_MEMORYSIZE_64,
	PAUSE_VM,
	RESUME_VM,
	SEARCH_MEMORY,
};

enum{
	RAX_REGISTER,
	RBX_REGISTER,
	RCX_REGISTER,
	RDX_REGISTER,
	R8_REGISTER,
	R9_REGISTER,
	R10_REGISTER,
	R11_REGISTER,
	R12_REGISTER,
	R13_REGISTER,
	R14_REGISTER,
	R15_REGISTER,
	RSP_REGISTER,
	RBP_REGISTER,
	RSI_REGISTER,
	RDI_REGISTER,
	RIP_REGISTER,
	DR0_REGISTER,
	DR1_REGISTER,
	DR2_REGISTER,
	DR3_REGISTER,
	DR6_REGISTER,
	DR7_REGISTER,
	CR3_REGISTER,
	CS_REGISTER,
	DS_REGISTER,
	ES_REGISTER,
	FS_REGISTER,
	GS_REGISTER,
	SS_REGISTER,
	RFLAGS_REGISTER,
};
char *registerName[] = {
	"rax","rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp", "rsi", "rdi", "rip",
	"dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
	"cr3",
	"cs", "ds", "es", "fs", "gs", "ss",
	"rflags"
};
uint64_t readPhysVM64(uint64_t physicalAddress, PUVM pUVM){
	uint64_t result;
	DBGFADDRESS Address;
	DBGFR3MemRead(pUVM, 0, DBGFR3AddrFromPhys(pUVM, &Address, physicalAddress), &result, sizeof(result));
	return result;
}

uint64_t LeftShift(uint64_t value, uint64_t count){ //TODO: ...
	for (int i = 0; i < count; i++){
		value = value << 1;
	}
	return value;
}

//Get potential virtual address from physical one.
uint64_t physical_virtual(uint64_t physical_addr, PUVM pUVM){
	DBGFREGVAL      Value;
    DBGFREGVALTYPE  enmType;
	DBGFR3RegNmQuery(pUVM, 0, "cr3", &Value, &enmType); //TODO: argument 
	uint64_t p_DirectoryTableBase = Value.u64;
				
	uint64_t PAGE_SIZE = 4096;
	uint64_t physicalMemorySize = 2147483648; //TODO:...
	uint64_t offset = physical_addr & 0xFFF;
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t PDPBA = readPhysVM64(p_DirectoryTableBase + (i * 8), pUVM) & 0x000FFFFFFFFFF000;
		if (PDPBA>0 && PDPBA<physicalMemorySize - PAGE_SIZE){
			uint64_t j;
			for (j = 0; j<512; j++){
				uint64_t PDBA = readPhysVM64(PDPBA + (j * 8), pUVM) & 0x000FFFFFFFFFF000;
				if (PDBA && PDBA<physicalMemorySize - PAGE_SIZE){
					uint64_t k;
					for (k = 0; k<512; k++){
						uint64_t PTBA = readPhysVM64(PDBA + (k * 8), pUVM) & 0x000FFFFFFFFFF000;
						if (PTBA && PTBA<physicalMemorySize - PAGE_SIZE){
							uint64_t l;
							for (l = 0; l<512; l++){
								uint64_t PPBA = readPhysVM64(PTBA + (l * 8), pUVM) & 0x000FFFFFFFFFF000;
								if (PPBA && PPBA<physicalMemorySize - PAGE_SIZE){
									if ((physical_addr & 0x000FFFFFFFFFF000) == (PPBA & 0x000FFFFFFFFFF000)){
										uint64_t virtual_addr = (LeftShift(i, 39) | LeftShift(j, 30) | LeftShift(k, 21) | LeftShift(l, 12) | offset);
										if (virtual_addr & 0x0000F00000000000){ //Canonical !
											virtual_addr = virtual_addr | 0xFFFFF00000000000;
										}
										//printf("virtualAddr = 0x%p => physicalAddr = 0x%016lX\n", virtual_addr, (PPBA&0x000FFFFFFFFFF000)|offset);
										return virtual_addr;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}

DWORD WINAPI debuggerServer(LPVOID lpParam) {
	PUVM pUVM = (PUVM)lpParam;
	HANDLE hPipe;
	CreateDBGNamedPipe(&hPipe);
	while (1){
		uint8_t cmd = Get8Pipe(hPipe);
		switch (cmd)
		{
		case PHYSICAL_VIRTUAL:{
			uint64_t physicalAddress = Get64Pipe(hPipe);
			uint64_t virtualAddress = physical_virtual(physicalAddress, pUVM);
			Put64Pipe(hPipe, virtualAddress);
			FlushFileBuffers(hPipe);
			break;
		}
		case RESUME_VM:
			printf("RESUME_VM !\n");
			VMR3Resume(pUVM, VMRESUMEREASON_USER);
			Put8Pipe(hPipe, 1);
			FlushFileBuffers(hPipe);
			break;
		case PAUSE_VM:
			printf("PAUSE_VM !\n");
			VMR3Suspend(pUVM, VMSUSPENDREASON_USER);
			Put8Pipe(hPipe, 1);
			FlushFileBuffers(hPipe);
			break;
		case GET_MEMORYSIZE_64:{
			uint64_t memorySize = (uint64_t)2147483648; //TODO handleGetMemorySize
			Put64Pipe(hPipe, memorySize); 
			FlushFileBuffers(hPipe);
			break;
		}
		case READ_REGISTER_64:{
			uint8_t registerId = Get8Pipe(hPipe);
			DBGFREGVAL      Value;
            DBGFREGVALTYPE  enmType;
			DBGFR3RegNmQuery(pUVM, 0, registerName[registerId], &Value, &enmType);
			//TODO : handleReadRegister
			Put64Pipe(hPipe, Value.u64);
			FlushFileBuffers(hPipe);
			break;
		}
		case READ_PHYSICAL:{
			uint64_t physicalAddress = Get64Pipe(hPipe);
			uint64_t size = Get64Pipe(hPipe);
			//printf("READ_PHYSICAL 0x%p\n", physicalAddress);
			uint8_t result[64*1024];
			DBGFADDRESS Address;
			DBGFR3MemRead(pUVM, 0, DBGFR3AddrFromPhys(pUVM, &Address, physicalAddress), result, size);
			for(int i=0; i<size; i++){
				Put8Pipe(hPipe, result[i]);
			}
			FlushFileBuffers(hPipe);
			break;
		}
		case READ_PHYSICAL_8:{
			uint64_t physicalAddress = Get64Pipe(hPipe);
			//printf("READ_PHYSICAL_8 0x%p\n", physicalAddress);
			uint8_t result;
			DBGFADDRESS Address;
			DBGFR3MemRead(pUVM, 0, DBGFR3AddrFromPhys(pUVM, &Address, physicalAddress), &result, sizeof(result));
			Put8Pipe(hPipe, result);
			FlushFileBuffers(hPipe);
			break;
		}
		case READ_PHYSICAL_32:{
			uint64_t physicalAddress = Get64Pipe(hPipe);
			//printf("READ_PHYSICAL_64 0x%p\n", physicalAddress);
			uint32_t result;
			DBGFADDRESS Address;
			DBGFR3MemRead(pUVM, 0, DBGFR3AddrFromPhys(pUVM, &Address, physicalAddress), &result, sizeof(result));
			Put32Pipe(hPipe, result);
			FlushFileBuffers(hPipe);
			break;
		}case READ_PHYSICAL_64:{
			uint64_t physicalAddress = Get64Pipe(hPipe);
			//printf("READ_PHYSICAL_32 0x%p\n", physicalAddress);
			uint64_t result = readPhysVM64(physicalAddress, pUVM);
			Put64Pipe(hPipe, result);
			FlushFileBuffers(hPipe);
			break;
		}
		case SEARCH_MEMORY:{
			char patternData[1024];
			uint64_t patternSize = Get64Pipe(hPipe);
			for(uint64_t i=0; i<patternSize; i++){
				patternData[i] = Get8Pipe(hPipe);
			}
			uint64_t startOffset = Get64Pipe(hPipe);
			//printf("startOffset %p\n", startOffset);
			//printf("patternSize %d\n", patternSize);
			
			DBGFADDRESS HitAddress;
			DBGFADDRESS Address;
			int rc = DBGFR3MemScan(pUVM, 0, DBGFR3AddrFromPhys(pUVM, &Address, startOffset), 2147483648, 1, patternData, patternSize, &HitAddress);
			uint64_t result = HitAddress.FlatPtr;
			if (RT_FAILURE(rc)){
				result = -1;
			}
			Put64Pipe(hPipe, result);	
			break;
		}
		default:
			printf("Unknown Command !\n");
			break;
		}
	}

	return 0;
}


/**
 * Spawns a new thread with a TCP based debugging console service.
 *
 * @returns VBox status.
 * @param   pUVM        The user mode VM handle.
 * @param   ppvData     Where to store a pointer to the instance data.
 */
DBGDECL(int)    DBGCTcpCreate(PUVM pUVM, void **ppvData)
{
	HANDLE thread = CreateThread(NULL, 0, debuggerServer, pUVM, 0, NULL);
	if (thread) {
		SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST);
	}
  
  
    /*
     * Check what the configuration says.
     */
    PCFGMNODE pKey = CFGMR3GetChild(CFGMR3GetRootU(pUVM), "DBGC");
    bool fEnabled;
    int rc = CFGMR3QueryBoolDef(pKey, "Enabled", &fEnabled,
#if defined(VBOX_WITH_DEBUGGER) && defined(VBOX_WITH_DEBUGGER_TCP_BY_DEFAULT) && !defined(__L4ENV__) && !defined(DEBUG_dmik)
        true
#else
        false
#endif
        );
    if (RT_FAILURE(rc))
        return VM_SET_ERROR_U(pUVM, rc, "Configuration error: Failed querying \"DBGC/Enabled\"");

    if (!fEnabled)
    {
        LogFlow(("DBGCTcpCreate: returns VINF_SUCCESS (Disabled)\n"));
        return VINF_SUCCESS;
    }

    /*
     * Get the port configuration.
     */
    uint32_t u32Port;
    rc = CFGMR3QueryU32Def(pKey, "Port", &u32Port, 5000);
    if (RT_FAILURE(rc))
        return VM_SET_ERROR_U(pUVM, rc, "Configuration error: Failed querying \"DBGC/Port\"");

    /*
     * Get the address configuration.
     */
    char szAddress[512];
    rc = CFGMR3QueryStringDef(pKey, "Address", szAddress, sizeof(szAddress), "");
    if (RT_FAILURE(rc))
        return VM_SET_ERROR_U(pUVM, rc, "Configuration error: Failed querying \"DBGC/Address\"");

    /*
     * Create the server (separate thread).
     */
    PRTTCPSERVER pServer;
    rc = RTTcpServerCreate(szAddress, u32Port, RTTHREADTYPE_DEBUGGER, "DBGC", dbgcTcpConnection, pUVM, &pServer);
    if (RT_SUCCESS(rc))
    {
        LogFlow(("DBGCTcpCreate: Created server on port %d %s\n", u32Port, szAddress));
        *ppvData = pServer;
        return rc;
    }

    LogFlow(("DBGCTcpCreate: returns %Rrc\n", rc));
    return VM_SET_ERROR_U(pUVM, rc, "Cannot start TCP-based debugging console service");
}


/**
 * Terminates any running TCP base debugger console service.
 *
 * @returns VBox status.
 * @param   pUVM            The user mode VM handle.
 * @param   pvData          The data returned by DBGCTcpCreate.
 */
DBGDECL(int) DBGCTcpTerminate(PUVM pUVM, void *pvData)
{
    /*
     * Destroy the server instance if any.
     */
    if (pvData)
    {
        int rc = RTTcpServerDestroy((PRTTCPSERVER)pvData);
        AssertRC(rc);
    }

    return VINF_SUCCESS;
}

