#include "stdafx.h"

#include <stdint.h>
#include <Windows.h>

#include "utils.h"
#include "FDP.h"


//TODO: move !!!!
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