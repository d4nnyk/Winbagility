#ifndef __DISSECTOR_H__
#define __DISSECTOR_H__

#include "kdserver.h"


uint64_t findDTB(const unsigned char *memory, uint64_t memSize);
uint64_t findKPCR(uint8_t cpuId, uint64_t DirectoryTableBase, const unsigned char *memory, uint64_t memSize);
uint64_t findDbgBreakPointWithStatus(const unsigned char *memory, uint64_t memSize);
uint64_t findKDBG(const unsigned char *memory, uint64_t memSize);
uint64_t findDebuggerDataList(uint64_t v_KDBG, const unsigned char *memory, uint64_t memSize);

//bool findPGkeys(analysisContext_t *context);
bool initialeAnalysis(analysisContext_t *context);
#endif //__DISSECTOR_H__