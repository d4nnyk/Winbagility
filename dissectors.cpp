#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "mmu.h"



uint64_t findDTB(const unsigned char *memory, uint64_t memSize){
	const char SystemEPROCESSPattern[] = { 'S', 'y', 's', 't', 'e', 'm', 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint64_t i;
	//for (i = 0x0; i<memSize - 4096; i++){
	for (i = memSize-PAGE_SIZE; i>0; i--){
		if (memcmp(memory + i + 0x438, SystemEPROCESSPattern, sizeof(SystemEPROCESSPattern)) == 0 //Is ImageFileName == "System" ?
			&& BYTESWAP64(read64(i + 0x2e0, memory)) == 0x04){ //Is PID == 4 ?
			printf("Physical System KPROCESS : 0x%p !\n", i);
			return BYTESWAP64(read64(i + 0x28, memory));
		}
	}
	return 0;
}


//Physical KPCR
uint64_t findKPCR(uint8_t cpuId, uint64_t DirectoryTableBase, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0x0; i<memSize / PAGE_SIZE; i++){
		uint64_t page_base = i*PAGE_SIZE;
		uint64_t tmp_value = BYTESWAP64(read64(page_base + 0x18, memory));
		uint64_t tmp_physical_addr = virtual_physical(tmp_value, DirectoryTableBase, memory, memSize);

		if (tmp_physical_addr
		&& tmp_physical_addr == page_base){//is KPCR->SelfPcr = @KPCR ?
			//Paranoid check !
			uint64_t CurrentPrc = BYTESWAP64(read64(page_base + 0x20, memory));
			uint64_t Prcb = virtual_physical(CurrentPrc, DirectoryTableBase, memory, memSize);
			if (Prcb == page_base + 0x180
			&& *(memory + page_base + 0x180 + 0x24) == cpuId){
				//printf("Physical KPCR : 0x%p !\n", i*PAGE_SIZE);
				//printf("Virtual KPCR  : 0x%p !\n", tmp_value);
				return page_base;
			}
		}
	}
	return 0;
}

//Physical DbgBreakPointWithStatus
uint64_t findDbgBreakPointWithStatus(const unsigned char *memory, uint64_t memSize){
	const char DbgBreakPointWithStatusPattern[] = { 0xCC, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x8B, 0xC8, 0x44 };
	uint64_t i;
	for (i = 0x0; i<memSize - 4096; i++){
		if (memcmp(memory + i, DbgBreakPointWithStatusPattern, sizeof(DbgBreakPointWithStatusPattern)) == 0 ){ 
			printf("Physical DbgBreakPointWithStatus : 0x%p !\n", i);
			//return BYTESWAP64(read64(i, memory));
			return i;
		}
	}
	return 0;
}

//Physical KDBG
uint64_t findKDBG(const unsigned char *memory, uint64_t memSize){
	const char KDBGPattern[] = { 'K', 'D', 'B', 'G' };
	uint64_t i;
	for (i = 0x0; i<memSize - 4096; i++){
		if (memcmp(memory + i + 0x10, KDBGPattern, sizeof(KDBGPattern)) == 0
		&& memcmp(memory + i, memory + i + 0x8, 8) == 0){ //HeadList check
			printf("Physical KDBG : 0x%p !\n", i);
			//return BYTESWAP64(read64(i, memory));
			return i;
		}
	}
	return 0;
}

//Physical DebuggerDataList
uint64_t findDebuggerDataList(uint64_t v_KDBG, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0x0; i<memSize - 4096; i++){
		if (memcmp(memory + i, &v_KDBG, 8) == 0
		&& memcmp(memory + i + 8, &v_KDBG, 8) == 0){
			//printf("Physical KDBG : 0x%p !\n", i);
			//return BYTESWAP64(read64(i, memory));
			return i;
		}
	}
	return 0;
}