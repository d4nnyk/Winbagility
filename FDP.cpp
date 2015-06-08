#include "stdafx.h"

#include <stdint.h>
#include <Windows.h>

#include "utils.h"
#include "FDP.h"

typedef struct FDP_clearBP_req{
	uint8_t cmdType;
	uint8_t breakPointId;
};

typedef struct FDP_setBP_req{
	uint8_t cmdType;
	uint8_t breakPointId;
	uint64_t breakAddress;
};

bool FDP_clearBP(uint8_t breakPointId, HANDLE toVMPipe){
	FDP_clearBP_req tmpReq;
	tmpReq.cmdType = CLEAR_BP;
	tmpReq.breakPointId = breakPointId;
	PutPipe(toVMPipe, (uint8_t*)&tmpReq, sizeof(tmpReq));
	FlushFileBuffers(toVMPipe);
	return Get8Pipe(toVMPipe);
}

bool FDP_setBP(uint8_t breakPointId, uint64_t breakAddress, HANDLE toVMPipe){
	FDP_setBP_req tmpReq;
	tmpReq.cmdType = SET_BP;
	tmpReq.breakPointId = breakPointId;
	tmpReq.breakAddress = breakAddress;
	PutPipe(toVMPipe, (uint8_t*)&tmpReq, sizeof(tmpReq));
	FlushFileBuffers(toVMPipe);
	return Get8Pipe(toVMPipe);
}

uint8_t FDP_pause(HANDLE toVMPipe){
	Put8Pipe(toVMPipe, PAUSE_VM);
	FlushFileBuffers(toVMPipe);
	uint8_t result = Get8Pipe(toVMPipe);
	return result;
}

uint8_t FDP_resume(HANDLE toVMPipe){
	Put8Pipe(toVMPipe, RESUME_VM);
	FlushFileBuffers(toVMPipe);
	uint8_t result = Get8Pipe(toVMPipe);
	return result;
}

uint64_t FDP_readRegister(HANDLE toVMPipe, uint8_t registerId){
	Put8Pipe(toVMPipe, READ_REGISTER_64);
	Put8Pipe(toVMPipe, registerId);
	FlushFileBuffers(toVMPipe);
	uint64_t result = Get64Pipe(toVMPipe);
	return result;
}

uint64_t FDP_searchMemory(uint8_t *patternData, uint64_t patternSize, uint64_t startOffset, HANDLE toVMPipe){
	Put8Pipe(toVMPipe, SEARCH_MEMORY);
	Put64Pipe(toVMPipe, patternSize);
	for (int i = 0; i < patternSize; i++){
		Put8Pipe(toVMPipe, patternData[i]);
	}
	Put64Pipe(toVMPipe, startOffset);

	return Get64Pipe(toVMPipe);
}

//Get potential virtual address from physical one.
uint64_t FDP_physical_virtual(uint64_t physical_addr, HANDLE toVMPipe){
	Put8Pipe(toVMPipe, PHYSICAL_VIRTUAL);
	Put64Pipe(toVMPipe, physical_addr);
	FlushFileBuffers(toVMPipe);
	uint64_t result = Get64Pipe(toVMPipe);
	return result;
}