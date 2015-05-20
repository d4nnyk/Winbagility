#ifndef __MMU_H__
#define __MMU_H__

#include "stdafx.h"

#include <stdint.h>
#include <windows.h>

#define PAGE_SIZE 4096
#define BYTESWAP64(x)                               \
        (((uint64_t)(x) << 56) |                           \
         (((uint64_t)(x) << 40) & 0X00FF000000000000ULL) | \
         (((uint64_t)(x) << 24) & 0X0000FF0000000000ULL) | \
         (((uint64_t)(x) << 8)  & 0X000000FF00000000ULL) | \
         (((uint64_t)(x) >> 8)  & 0X00000000FF000000ULL) | \
         (((uint64_t)(x) >> 24) & 0X0000000000FF0000ULL) | \
         (((uint64_t)(x) >> 40) & 0X000000000000FF00ULL) | \
         ((uint64_t)(x)  >> 56))

uint64_t read64(uint64_t addr, const unsigned char* memory);

void parsePML4E(uint64_t base, const unsigned char *memory, uint64_t memSize);
uint64_t physical_virtual(uint64_t physical_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize);
uint64_t virtual_physical(uint64_t virtual_addr, uint64_t PML4E_base, const unsigned char *memory, uint64_t memSize);


void readMMU(char *dst, uint64_t virtualAddr, uint64_t DirectoryTableBase, const unsigned char* memory, uint32_t size);
#endif //__MMU_H__