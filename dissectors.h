
#include <stdint.h> //TODO: remove !

uint64_t findDTB(const unsigned char *memory, uint64_t memSize);
uint64_t findKPCR(uint8_t cpuId, uint64_t DirectoryTableBase, const unsigned char *memory, uint64_t memSize);
uint64_t findDbgBreakPointWithStatus(const unsigned char *memory, uint64_t memSize);
uint64_t findKDBG(const unsigned char *memory, uint64_t memSize);
uint64_t findDebuggerDataList(uint64_t v_KDBG, const unsigned char *memory, uint64_t memSize);