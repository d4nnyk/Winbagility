#ifndef __MMU_H__
#define __MMU_H__

#include "stdafx.h"

#include <stdint.h>
#include <windows.h>

#include "kdserver.h"

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
//#define BYTESWAP64(x) x //TODO: remove it !

bool readPhysical(uint8_t *dstBuffer, uint64_t size, uint64_t physicalAdress, analysisContext_t *context);
uint8_t readPhysical8(uint64_t physicalAdress, analysisContext_t *context);
uint32_t readPhysical32(uint64_t physicalAdress, analysisContext_t *context);
uint64_t readPhysical64(uint64_t physicalAdress, analysisContext_t *context);

void parsePML4E(uint64_t base, const unsigned char *memory, uint64_t memSize);
uint64_t physical_virtual(uint64_t physical_addr, analysisContext_t *context);
uint64_t virtual_physical(uint64_t virtual_addr, analysisContext_t *context);


void readMMU(uint8_t *dst, uint32_t size, uint64_t virtualAddr, analysisContext_t *context);
uint64_t searchMemory(uint8_t *patternData, uint64_t patternSize, uint64_t startOffset, analysisContext_t *context);
#endif //__MMU_H__