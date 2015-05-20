#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "mmu.h"


uint64_t LeftShift(uint64_t value, uint64_t count){ //TODO: ...
	for (int i = 0; i < count; i++){
		value = value << 1;
	}
	return value;
}

uint64_t read64(uint64_t addr, const unsigned char* memory){
	uint64_t tmp;
	memcpy(&tmp, memory + addr, 8);
	return BYTESWAP64(tmp);
}

void parsePTE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = BYTESWAP64(read64(base + (i * 8), memory));
		uint64_t PPBA = tmp & 0x000FFFFFFFFFF000;
		if (PPBA && PPBA<memSize){
			printf("virtualAddr = 0x%016lX => physicalAddr = 0x%016lX\n", virtualAddr | LeftShift(i, 12), PPBA & 0x3FFFFFFF);
		}
	}
}

void parsePDE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = BYTESWAP64(read64(base + (i * 8), memory));
		uint64_t PTBA = tmp & 0x000FFFFFFFFFF000;
		if (PTBA && PTBA<memSize){
			parsePTE(PTBA, virtualAddr | LeftShift(i, 21), memory, memSize);
		}
	}
}

void parsePDPE(uint64_t base, uint64_t virtualAddr, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = BYTESWAP64(read64(base + (i * 8), memory));
		uint64_t PDBA = tmp & 0x000FFFFFFFFFF000;
		if (PDBA && PDBA<memSize){
			parsePDE(PDBA, virtualAddr | LeftShift(i, 30), memory, memSize);
		}
	}
}

void parsePML4E(uint64_t base, const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t tmp = BYTESWAP64(read64(base + (i * 8), memory));
		uint64_t PDPBA = tmp & 0x000FFFFFFFFFF000;
		if (PDPBA && PDPBA<memSize){
			parsePDPE(PDPBA, LeftShift(i, 39), memory, memSize);
		}
	}
}



//Get potential virtual address from physical one.
uint64_t physical_virtual(uint64_t physical_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize){
	uint64_t offset = physical_addr & 0xFFF;
	uint64_t i;
	for (i = 0; i<512; i++){
		uint64_t PDPBA = BYTESWAP64(read64(PML4E_base + (i * 8), memory)) & 0x000FFFFFFFFFF000;
		if (PDPBA>0 && PDPBA<memSize - PAGE_SIZE){
			uint64_t j;
			for (j = 0; j<512; j++){
				uint64_t PDBA = BYTESWAP64(read64(PDPBA + (j * 8), memory)) & 0x000FFFFFFFFFF000;
				if (PDBA && PDBA<memSize - PAGE_SIZE){
					uint64_t k;
					for (k = 0; k<512; k++){
						uint64_t PTBA = BYTESWAP64(read64(PDBA + (k * 8), memory)) & 0x000FFFFFFFFFF000;
						if (PTBA && PTBA<memSize - PAGE_SIZE){
							uint64_t l;
							for (l = 0; l<512; l++){
								uint64_t PPBA = BYTESWAP64(read64(PTBA + (l * 8), memory)) & 0x000FFFFFFFFFF000;
								if (PPBA && PPBA<memSize - PAGE_SIZE){
									if ((physical_addr & 0x000FFFFFFFFFF000) == (PPBA & 0x000FFFFFFFFFF000)){
										uint64_t virtual_addr = (LeftShift(i,39) | LeftShift(j,30) | LeftShift(k, 21) | LeftShift(l, 12) | offset);
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


uint64_t virtual_physical(uint64_t virtual_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize){
	uint64_t PML4E_index = (virtual_addr & 0x0000FF8000000000) >> (9 + 9 + 9 + 12);
	uint64_t PDPE_index = (virtual_addr & 0x0000007FC0000000) >> (9 + 9 + 12);
	uint64_t PDE_index = (virtual_addr & 0x000000003FE00000) >> (9 + 12);
	uint64_t PTE_index = (virtual_addr & 0x00000000001FF000) >> (12);
	uint64_t P_offset = (virtual_addr & 0x0000000000000FFF);

	uint64_t PDPE_base = BYTESWAP64(read64(PML4E_base + (PML4E_index * 8), memory)) & 0x0000FFFFFFFFF000;
	//printf("PDPE_base %016lx\n", PDPE_base);
	if (PDPE_base == 0
	|| PDPE_base > memSize - PAGE_SIZE){
		return 0;
	}

	uint64_t PDE_base = BYTESWAP64(read64(PDPE_base + (PDPE_index * 8), memory)) & 0x0000FFFFFFFFF000;
	//printf("PDE_base %016lx\n", PDE_base);
	if (PDE_base == 0
	|| PDE_base > memSize - PAGE_SIZE){
		return 0;
	}

	uint64_t tmp = BYTESWAP64(read64(PDE_base + (PDE_index * 8), memory));
	uint64_t PTE_base = tmp & 0x0000FFFFFFFFF000;
	//printf("PTE_base %016lx\n", PTE_base);
	if (PTE_base == 0
	|| PTE_base > memSize - PAGE_SIZE){
		return 0;
	}
	if (tmp & 0x0000000000000080){ //This page is a large one (2M) !
		uint64_t tmpPhysical = ((tmp & 0x0000000FFFE00000) | (virtual_addr & 0x00000000001FFFFF));
		if (tmpPhysical == 0
		|| tmpPhysical > (memSize - (2 * 1024 * 1024))){
			return 0;
		}
		return tmpPhysical;
	}

	uint64_t P_base = BYTESWAP64(read64(PTE_base + (PTE_index * 8), memory)) & 0x0000FFFFFFFFF000;
	//printf("P_base %016lx\n", P_base);
	if (P_base == 0
	|| P_base > memSize - PAGE_SIZE){
		return 0;
	}

	return (P_base | P_offset);
}

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

//TODO: !!!!!!!!!!
void readMMU(char *dst, uint64_t virtualAddr, uint64_t DirectoryTableBase, const unsigned char* memory, uint32_t size){
	uint64_t physical = virtual_physical(virtualAddr, DirectoryTableBase, memory, 2 * 1024 * 1024 * 1024);
	uint64_t pageEnd = (physical & 0xFFFFFFFFFFFFF000) + PAGE_SIZE;
	uint64_t readBytes = MIN(pageEnd - physical, size);
	memcpy(dst, memory + physical, readBytes); //First Read
	int64_t leftToRead = size - readBytes;
	if (leftToRead > 0){ //More than 1 page to access !
		while (leftToRead >= PAGE_SIZE){
			physical = virtual_physical(virtualAddr + readBytes, DirectoryTableBase, memory, 2 * 1024 * 1024 * 1024);
			memcpy(dst + readBytes, memory + physical, PAGE_SIZE);
			leftToRead = leftToRead - PAGE_SIZE;
			readBytes = readBytes + PAGE_SIZE;
		}
		if (leftToRead > 0){ //Bytes left
			physical = virtual_physical(virtualAddr + readBytes, DirectoryTableBase, memory, 2 * 1024 * 1024 * 1024);
			memcpy(dst + readBytes, memory + physical, leftToRead);
		}
	}
}