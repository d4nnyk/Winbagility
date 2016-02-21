#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>


#include "mmu.h"
#include "kdserver.h"
#include "FDP.h"
#include "utils.h"



//TODO: bool !
uint64_t WDBG_searchPhysicalMemory(uint8_t *patternData, uint64_t patternSize, uint64_t startOffset, analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){
		return FDP_searchMemory(patternData, patternSize, startOffset, context->toVMPipe);
	}

	for (uint64_t i = startOffset; i < context->physicalMemorySize - 4096; i++){
		if (memcmp(context->physicalMemory + i, patternData, patternSize) == 0){
			return i;
		}
	}
	return 0;
}

uint64_t LeftShift(uint64_t value, uint64_t count){ //TODO: ...
	for (int i = 0; i < count; i++){
		value = value << 1;
	}
	return value;
}

//TODO: move in FDP.cpp
bool readPhysical(uint8_t *dstBuffer, uint64_t size, uint64_t physicalAdress, analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){
		Put8Pipe(context->toVMPipe, READ_PHYSICAL);
		Put64Pipe(context->toVMPipe, physicalAdress);
		Put64Pipe(context->toVMPipe, size);
		FlushFileBuffers(context->toVMPipe);
		for (int i = 0; i < size; i++){
			dstBuffer[i] = Get8Pipe(context->toVMPipe);
		}
	}else{
		if (physicalAdress > context->physicalMemorySize){
			return false;
		}
		memcpy(dstBuffer, context->physicalMemory + physicalAdress, size);
	}
	return true;
}

uint8_t readPhysical8(uint64_t physicalAddress, analysisContext_t *context){
	uint8_t result;
	if (context->curMode == STOCK_VBOX_TYPE){
		Put8Pipe(context->toVMPipe, READ_PHYSICAL_8);
		Put64Pipe(context->toVMPipe, physicalAddress);
		FlushFileBuffers(context->toVMPipe);
		result = Get8Pipe(context->toVMPipe);
	}else{
		readPhysical(&result, sizeof(result), physicalAddress, context);
	}
	return result;
}

uint32_t readPhysical32(uint64_t physicalAddress, analysisContext_t *context){
	uint32_t result;
	if (context->curMode == STOCK_VBOX_TYPE){
		Put8Pipe(context->toVMPipe, READ_PHYSICAL_32);
		Put64Pipe(context->toVMPipe, physicalAddress);
		FlushFileBuffers(context->toVMPipe);
		result = Get32Pipe(context->toVMPipe);
	}else{
		readPhysical((uint8_t*)&result, sizeof(result), physicalAddress, context);
	}
	return result;
}

uint64_t readPhysical64(uint64_t physicalAddress, analysisContext_t *context){
	uint64_t result;
	if (context->curMode == STOCK_VBOX_TYPE){
		Put8Pipe(context->toVMPipe, READ_PHYSICAL_64);
		Put64Pipe(context->toVMPipe, physicalAddress);
		FlushFileBuffers(context->toVMPipe);
		result = Get64Pipe(context->toVMPipe);
	}else{
		readPhysical((uint8_t*)&result, sizeof(result), physicalAddress, context);
	}
	return result;
}

void parsePTE(uint64_t base, uint64_t virtualAddr, analysisContext_t *context){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = readPhysical64(base + (i * 8), context);
		uint64_t PPBA = tmp & 0x000FFFFFFFFFF000;
		if (PPBA && PPBA<context->physicalMemorySize){
			printf("virtualAddr = 0x%016lX => physicalAddr = 0x%016lX\n", virtualAddr | LeftShift(i, 12), PPBA & 0x3FFFFFFF);
		}
	}
}

void parsePDE(uint64_t base, uint64_t virtualAddr, analysisContext_t *context){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = readPhysical64(base + (i * 8), context);
		uint64_t PTBA = tmp & 0x000FFFFFFFFFF000;
		if (PTBA && PTBA<context->physicalMemorySize){
			parsePTE(PTBA, virtualAddr | LeftShift(i, 21), context);
		}
	}
}

void parsePDPE(uint64_t base, uint64_t virtualAddr, analysisContext_t *context){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = readPhysical64(base + (i * 8), context);
		uint64_t PDBA = tmp & 0x000FFFFFFFFFF000;
		if (PDBA && PDBA<context->physicalMemorySize){
			parsePDE(PDBA, virtualAddr | LeftShift(i, 30), context);
		}
	}
}

void parsePML4E(uint64_t base, analysisContext_t *context){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = readPhysical64(base + (i * 8), context);
		uint64_t PDPBA = tmp & 0x000FFFFFFFFFF000;
		if (PDPBA && PDPBA<context->physicalMemorySize){
			parsePDPE(PDPBA, LeftShift(i, 39), context);
		}
	}
}


uint64_t physical_virtual(uint64_t physical_addr, analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){ //TODO: function pointer
		return FDP_physical_virtual(physical_addr, context->toVMPipe);
	}
	uint64_t offset = physical_addr & 0xFFF;
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t PDPBA = readPhysical64(context->p_DirectoryTableBase + (i * 8), context) & 0x000FFFFFFFFFF000;
		if (PDPBA>0 && PDPBA<context->physicalMemorySize - PAGE_SIZE){
			uint64_t j;
			for (j = 0; j<512; j++){
				uint64_t PDBA = readPhysical64(PDPBA + (j * 8), context) & 0x000FFFFFFFFFF000;
				if (PDBA && PDBA<context->physicalMemorySize - PAGE_SIZE){
					uint64_t k;
					for (k = 0; k<512; k++){
						uint64_t PTBA = readPhysical64(PDBA + (k * 8), context) & 0x000FFFFFFFFFF000;
						if (PTBA && PTBA<context->physicalMemorySize - PAGE_SIZE){
							uint64_t l;
							for (l = 0; l<512; l++){
								uint64_t PPBA = readPhysical64(PTBA + (l * 8), context) & 0x000FFFFFFFFFF000;
								if (PPBA && PPBA<context->physicalMemorySize - PAGE_SIZE){
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


uint64_t virtual_physical(uint64_t virtual_addr, analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){ //TODO: function pointer
		return FDP_virtual_physical(virtual_addr, context->toVMPipe);
	}
	uint64_t PML4E_index = (virtual_addr & 0x0000FF8000000000) >> (9 + 9 + 9 + 12);
	uint64_t PDPE_index = (virtual_addr & 0x0000007FC0000000) >> (9 + 9 + 12);
	uint64_t PDE_index = (virtual_addr & 0x000000003FE00000) >> (9 + 12);
	uint64_t PTE_index = (virtual_addr & 0x00000000001FF000) >> (12);
	uint64_t P_offset = (virtual_addr & 0x0000000000000FFF);

	uint64_t PDPE_base = readPhysical64(context->p_DirectoryTableBase + (PML4E_index * 8), context) & 0x0000FFFFFFFFF000;
	//printf("PDPE_base %016lx\n", PDPE_base);
	if (PDPE_base == 0
		|| PDPE_base > context->physicalMemorySize - PAGE_SIZE){
		return 0;
	}

	uint64_t PDE_base = readPhysical64(PDPE_base + (PDPE_index * 8), context) & 0x0000FFFFFFFFF000;
	//printf("PDE_base %016lx\n", PDE_base);
	if (PDE_base == 0
		|| PDE_base > context->physicalMemorySize - PAGE_SIZE){
		return 0;
	}

	uint64_t tmp = readPhysical64(PDE_base + (PDE_index * 8), context);
	uint64_t PTE_base = tmp & 0x0000FFFFFFFFF000;
	//printf("PTE_base %016lx\n", PTE_base);
	if (PTE_base == 0
		|| PTE_base > context->physicalMemorySize - PAGE_SIZE){
		return 0;
	}
	if (tmp & 0x0000000000000080){ //This page is a large one (2M) !
		uint64_t tmpPhysical = ((tmp & 0x0000000FFFE00000) | (virtual_addr & 0x00000000001FFFFF));
		if (tmpPhysical == 0
			|| tmpPhysical > (context->physicalMemorySize - (2 * 1024 * 1024))){
			return 0;
		}
		return tmpPhysical;
	}

	uint64_t P_base = readPhysical64(PTE_base + (PTE_index * 8), context) & 0x0000FFFFFFFFF000;
	//printf("P_base %016lx\n", P_base);
	if (P_base == 0
		|| P_base > context->physicalMemorySize - PAGE_SIZE){
		return 0;
	}

	return (P_base | P_offset);
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

//TODO: !!!!!!!!!!
void readMMU(uint8_t *dst, uint32_t size, uint64_t virtualAddr, analysisContext_t *context){
	uint64_t physicalAddress = virtual_physical(virtualAddr, context);
	uint64_t pageEnd = (physicalAddress & 0xFFFFFFFFFFFFF000) + PAGE_SIZE;
	uint64_t readBytes = MIN(pageEnd - physicalAddress, size);
	readPhysical(dst, readBytes, physicalAddress, context);
	int64_t leftToRead = size - readBytes;
	if (leftToRead > 0){ //More than 1 page to access !
		while (leftToRead >= PAGE_SIZE){
			physicalAddress = virtual_physical(virtualAddr + readBytes, context);
			readPhysical(dst + readBytes, PAGE_SIZE, physicalAddress, context);
			leftToRead = leftToRead - PAGE_SIZE;
			readBytes = readBytes + PAGE_SIZE;
		}
		if (leftToRead > 0){ //Bytes left
			physicalAddress = virtual_physical(virtualAddr + readBytes, context);
			readPhysical(dst + readBytes, leftToRead, physicalAddress, context);
		}
	}
}

bool WDBG_searchVirtualMemory(uint8_t *patternData, uint64_t patternSize, uint64_t startVirtualAddress, uint64_t endOffset, uint64_t *foundVirtualAddress, analysisContext_t *context){
	//TODO: FDP stub !!!
	uint64_t curOffset = 0;
	uint8_t tmpBuffer[PAGE_SIZE];
	uint64_t leftToLook = endOffset - curOffset;
	while (leftToLook){
		readMMU(tmpBuffer, PAGE_SIZE, startVirtualAddress + curOffset, context); //TODO: optimisation no copy !
		for (int i = 0; i < MIN(PAGE_SIZE - patternSize, leftToLook); i++){
			if (memcmp(tmpBuffer + i, patternData, patternSize) == 0){
				*foundVirtualAddress = startVirtualAddress + curOffset + i;
				return true;
			}
		}
		curOffset = curOffset + MIN(leftToLook, PAGE_SIZE - patternSize);
		leftToLook = endOffset - curOffset;
	}
	*foundVirtualAddress = 0;
	return false;
}