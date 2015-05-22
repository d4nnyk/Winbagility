#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>


#include "dissectors.h"
#include "kdserver.h"
#include "mmu.h"

void printKDBG(_KDDEBUGGER_DATA64 *tmpKDBG){
	printf("-------------KDBG-----------------------\n");
	printf("List[0] : %p\n", tmpKDBG->Header.List[0]);
	printf("List[1] : %p\n", tmpKDBG->Header.List[1]);
	printf("OwnerTag : %04x\n", tmpKDBG->Header.OwnerTag);
	printf("Size : %04x\n", tmpKDBG->Header.Size);
	printf("KernBase : %p\n", tmpKDBG->KernBase);
	printf("BreakpointWithStatus : %p\n", tmpKDBG->BreakpointWithStatus);
	printf("SavedContext : %p\n", tmpKDBG->SavedContext);
	printf("ThCallbackStack : %04x\n", tmpKDBG->ThCallbackStack);
	printf("NextCallback : %04x\n", tmpKDBG->NextCallback);
	printf("FramePointer : %04x\n", tmpKDBG->FramePointer);
	printf("PaeEnabled : %04x\n", tmpKDBG->PaeEnabled);
	printf("KiCallUserMode : %p\n", tmpKDBG->KiCallUserMode);
	printf("KeUserCallbackDispatcher : %p\n", tmpKDBG->KeUserCallbackDispatcher);
	printf("PsLoadedModuleList : %p\n", tmpKDBG->PsLoadedModuleList);
	printf("PsActiveProcessHead : %p\n", tmpKDBG->PsActiveProcessHead);
	printf("PspCidTable : %p\n", tmpKDBG->PspCidTable);
	printf("ExpSystemResourcesList : %p\n", tmpKDBG->ExpSystemResourcesList);
	printf("ExpPagedPoolDescriptor : %p\n", tmpKDBG->ExpPagedPoolDescriptor);
	printf("ExpNumberOfPagedPools : %p\n", tmpKDBG->ExpNumberOfPagedPools);
	printf("KeTimeIncrement : %p\n", tmpKDBG->KeTimeIncrement);
	printf("KeBugCheckCallbackListHead : %p\n", tmpKDBG->KeBugCheckCallbackListHead);
	printf("KiBugcheckData : %p\n", tmpKDBG->KiBugcheckData);
	printf("IopErrorLogListHead : %p\n", tmpKDBG->IopErrorLogListHead);
	printf("ObpRootDirectoryObject : %p\n", tmpKDBG->ObpRootDirectoryObject);
	printf("ObpTypeObjectType : %p\n", tmpKDBG->ObpTypeObjectType);
	printf("MmSystemCacheStart : %p\n", tmpKDBG->MmSystemCacheStart);
	printf("MmSystemCacheEnd : %p\n", tmpKDBG->MmSystemCacheEnd);
	printf("MmSystemCacheWs : %p\n", tmpKDBG->MmSystemCacheWs);
	printf("MmPfnDatabase : %p\n", tmpKDBG->MmPfnDatabase);
	printf("MmSystemPtesStart : %p\n", tmpKDBG->MmSystemPtesStart);
	printf("MmSystemPtesEnd : %p\n", tmpKDBG->MmSystemPtesEnd);
	printf("MmSubsectionBase : %p\n", tmpKDBG->MmSubsectionBase);
	printf("MmNumberOfPagingFiles : %p\n", tmpKDBG->MmNumberOfPagingFiles);
	printf("MmLowestPhysicalPage : %p\n", tmpKDBG->MmLowestPhysicalPage);
	printf("MmHighestPhysicalPage : %p\n", tmpKDBG->MmHighestPhysicalPage);
	printf("MmNumberOfPhysicalPages : %p\n", tmpKDBG->MmNumberOfPhysicalPages);
	printf("MmMaximumNonPagedPoolInBytes : %p\n", tmpKDBG->MmMaximumNonPagedPoolInBytes);
	printf("MmNonPagedSystemStart : %p\n", tmpKDBG->MmNonPagedSystemStart);
	printf("MmNonPagedPoolStart : %p\n", tmpKDBG->MmNonPagedPoolStart);
	printf("MmNonPagedPoolEnd : %p\n", tmpKDBG->MmNonPagedPoolEnd);
	printf("MmPagedPoolStart : %p\n", tmpKDBG->MmPagedPoolStart);
	printf("MmPagedPoolEnd : %p\n", tmpKDBG->MmPagedPoolEnd);
	printf("MmPagedPoolInformation : %p\n", tmpKDBG->MmPagedPoolInformation);
	printf("MmPageSize : %p\n", tmpKDBG->MmPageSize);
	printf("MmSizeOfPagedPoolInBytes : %p\n", tmpKDBG->MmSizeOfPagedPoolInBytes);
	printf("MmTotalCommitLimit : %p\n", tmpKDBG->MmTotalCommitLimit);
	printf("MmTotalCommittedPages : %p\n", tmpKDBG->MmTotalCommittedPages);
	printf("MmSharedCommit : %p\n", tmpKDBG->MmSharedCommit);
	printf("MmDriverCommit : %p\n", tmpKDBG->MmDriverCommit);
	printf("MmProcessCommit : %p\n", tmpKDBG->MmProcessCommit);
	printf("MmPagedPoolCommit : %p\n", tmpKDBG->MmPagedPoolCommit);
	printf("MmExtendedCommit : %p\n", tmpKDBG->MmExtendedCommit);
	printf("MmZeroedPageListHead : %p\n", tmpKDBG->MmZeroedPageListHead);
	printf("MmFreePageListHead : %p\n", tmpKDBG->MmFreePageListHead);
	printf("MmStandbyPageListHead : %p\n", tmpKDBG->MmStandbyPageListHead);
	printf("MmModifiedPageListHead : %p\n", tmpKDBG->MmModifiedPageListHead);
	printf("MmModifiedNoWritePageListHead : %p\n", tmpKDBG->MmModifiedNoWritePageListHead);
	printf("MmAvailablePages : %p\n", tmpKDBG->MmAvailablePages);
	printf("MmResidentAvailablePages : %p\n", tmpKDBG->MmResidentAvailablePages);
	printf("PoolTrackTable : %p\n", tmpKDBG->PoolTrackTable);
	printf("NonPagedPoolDescriptor : %p\n", tmpKDBG->NonPagedPoolDescriptor);
	printf("MmHighestUserAddress : %p\n", tmpKDBG->MmHighestUserAddress);
	printf("MmSystemRangeStart : %p\n", tmpKDBG->MmSystemRangeStart);
	printf("MmUserProbeAddress : %p\n", tmpKDBG->MmUserProbeAddress);
	printf("KdPrintCircularBuffer : %p\n", tmpKDBG->KdPrintCircularBuffer);
	printf("KdPrintCircularBufferEnd : %p\n", tmpKDBG->KdPrintCircularBufferEnd);
	printf("KdPrintWritePointer : %p\n", tmpKDBG->KdPrintWritePointer);
	printf("KdPrintRolloverCount : %p\n", tmpKDBG->KdPrintRolloverCount);
	printf("MmLoadedUserImageList : %p\n", tmpKDBG->MmLoadedUserImageList);
	printf("NtBuildLab : %p\n", tmpKDBG->NtBuildLab);
	printf("KiNormalSystemCall : %p\n", tmpKDBG->KiNormalSystemCall);
	printf("KiProcessorBlock : %p\n", tmpKDBG->KiProcessorBlock);
	printf("MmUnloadedDrivers : %p\n", tmpKDBG->MmUnloadedDrivers);
	printf("MmLastUnloadedDriver : %p\n", tmpKDBG->MmLastUnloadedDriver);
	printf("MmTriageActionTaken : %p\n", tmpKDBG->MmTriageActionTaken);
	printf("MmSpecialPoolTag : %p\n", tmpKDBG->MmSpecialPoolTag);
	printf("KernelVerifier : %p\n", tmpKDBG->KernelVerifier);
	printf("MmVerifierData : %p\n", tmpKDBG->MmVerifierData);
	printf("MmAllocatedNonPagedPool : %p\n", tmpKDBG->MmAllocatedNonPagedPool);
	printf("MmPeakCommitment : %p\n", tmpKDBG->MmPeakCommitment);
	printf("MmTotalCommitLimitMaximum : %p\n", tmpKDBG->MmTotalCommitLimitMaximum);
	printf("CmNtCSDVersion : %p\n", tmpKDBG->CmNtCSDVersion);
	printf("MmPhysicalMemoryBlock : %p\n", tmpKDBG->MmPhysicalMemoryBlock);
	printf("MmSessionBase : %p\n", tmpKDBG->MmSessionBase);
	printf("MmSessionSize : %p\n", tmpKDBG->MmSessionSize);
	printf("MmSystemParentTablePage : %p\n", tmpKDBG->MmSystemParentTablePage);
	printf("MmVirtualTranslationBase : %p\n", tmpKDBG->MmVirtualTranslationBase);
	printf("OffsetKThreadNextProcessor : %04x\n", tmpKDBG->OffsetKThreadNextProcessor);
	printf("OffsetKThreadTeb : %04x\n", tmpKDBG->OffsetKThreadTeb);
	printf("OffsetKThreadKernelStack : %04x\n", tmpKDBG->OffsetKThreadKernelStack);
	printf("OffsetKThreadInitialStack : %04x\n", tmpKDBG->OffsetKThreadInitialStack);
	printf("OffsetKThreadApcProcess : %04x\n", tmpKDBG->OffsetKThreadApcProcess);
	printf("OffsetKThreadState : %04x\n", tmpKDBG->OffsetKThreadState);
	printf("OffsetKThreadBStore : %04x\n", tmpKDBG->OffsetKThreadBStore);
	printf("OffsetKThreadBStoreLimit : %04x\n", tmpKDBG->OffsetKThreadBStoreLimit);
	printf("SizeEProcess : %04x\n", tmpKDBG->SizeEProcess);
	printf("OffsetEprocessPeb : %04x\n", tmpKDBG->OffsetEprocessPeb);
	printf("OffsetEprocessParentCID : %04x\n", tmpKDBG->OffsetEprocessParentCID);
	printf("OffsetEprocessDirectoryTableBase : %04x\n", tmpKDBG->OffsetEprocessDirectoryTableBase);
	printf("SizePrcb : %04x\n", tmpKDBG->SizePrcb);
	printf("OffsetPrcbDpcRoutine : %04x\n", tmpKDBG->OffsetPrcbDpcRoutine);
	printf("OffsetPrcbCurrentThread : %04x\n", tmpKDBG->OffsetPrcbCurrentThread);
	printf("OffsetPrcbMhz : %04x\n", tmpKDBG->OffsetPrcbMhz);
	printf("OffsetPrcbCpuType : %04x\n", tmpKDBG->OffsetPrcbCpuType);
	printf("OffsetPrcbVendorString : %04x\n", tmpKDBG->OffsetPrcbVendorString);
	printf("OffsetPrcbProcStateContext : %04x\n", tmpKDBG->OffsetPrcbProcStateContext);
	printf("OffsetPrcbNumber : %04x\n", tmpKDBG->OffsetPrcbNumber);
	printf("SizeEThread : %04x\n", tmpKDBG->SizeEThread);
	printf("KdPrintCircularBufferPtr : %p\n", tmpKDBG->KdPrintCircularBufferPtr);
	printf("KdPrintBufferSize : %p\n", tmpKDBG->KdPrintBufferSize);
	printf("KeLoaderBlock : %p\n", tmpKDBG->KeLoaderBlock);
	printf("SizePcr : %04x\n", tmpKDBG->SizePcr);
	printf("OffsetPcrSelfPcr : %04x\n", tmpKDBG->OffsetPcrSelfPcr);
	printf("OffsetPcrCurrentPrcb : %04x\n", tmpKDBG->OffsetPcrCurrentPrcb);
	printf("OffsetPcrContainedPrcb : %04x\n", tmpKDBG->OffsetPcrContainedPrcb);
	printf("OffsetPcrInitialBStore : %04x\n", tmpKDBG->OffsetPcrInitialBStore);
	printf("OffsetPcrBStoreLimit : %04x\n", tmpKDBG->OffsetPcrBStoreLimit);
	printf("OffsetPcrInitialStack : %04x\n", tmpKDBG->OffsetPcrInitialStack);
	printf("OffsetPcrStackLimit : %04x\n", tmpKDBG->OffsetPcrStackLimit);
	printf("OffsetPrcbPcrPage : %04x\n", tmpKDBG->OffsetPrcbPcrPage);
	printf("OffsetPrcbProcStateSpecialReg : %04x\n", tmpKDBG->OffsetPrcbProcStateSpecialReg);
	printf("GdtR0Code : %04x\n", tmpKDBG->GdtR0Code);
	printf("GdtR0Data : %04x\n", tmpKDBG->GdtR0Data);
	printf("GdtR0Pcr : %04x\n", tmpKDBG->GdtR0Pcr);
	printf("GdtR3Code : %04x\n", tmpKDBG->GdtR3Code);
	printf("GdtR3Data : %04x\n", tmpKDBG->GdtR3Data);
	printf("GdtR3Teb : %04x\n", tmpKDBG->GdtR3Teb);
	printf("GdtLdt : %04x\n", tmpKDBG->GdtLdt);
	printf("GdtTss : %04x\n", tmpKDBG->GdtTss);
	printf("Gdt64R3CmCode : %04x\n", tmpKDBG->Gdt64R3CmCode);
	printf("Gdt64R3CmTeb : %04x\n", tmpKDBG->Gdt64R3CmTeb);
	printf("IopNumTriageDumpDataBlocks : %p\n", tmpKDBG->IopNumTriageDumpDataBlocks);
	printf("IopTriageDumpDataBlocks : %p\n", tmpKDBG->IopTriageDumpDataBlocks);
	printf("VfCrashDataBlock : %p\n", tmpKDBG->VfCrashDataBlock);
	printf("----------------------------------------\n");
}



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

inline uint64_t _rol64(uint64_t v, uint64_t s){
	return (v << s) | (v >> (64 - s));
}

inline uint64_t uncipherData(uint64_t data, uint64_t KiWaitNever, uint64_t KiWaitAlways, uint64_t KdpDataBlockEncoded){
	data = data^KiWaitNever;
	data = _rol64(data, KiWaitNever & 0xFF);
	data = data^KdpDataBlockEncoded;
	data = BYTESWAP64(data);
	data = data^KiWaitAlways;
	return data;
}

/*
nt!KdCopyDataBlock:
fffff803`451e0c54 803db6250d0000  cmp     byte ptr [nt!KdpDataBlockEncoded (fffff803`452b3211)],0
fffff803`451e0c5b 4c8bd1          mov     r10,rcx
fffff803`451e0c5e 4c8d0dcb680c00  lea     r9,[nt!KdDebuggerDataBlock (fffff803`452a7530)]
fffff803`451e0c65 743d            je      nt!KdCopyDataBlock+0x50 (fffff803`451e0ca4)
fffff803`451e0c67 41b86c000000    mov     r8d,6Ch
fffff803`451e0c6d 4d2bd1          sub     r10,r9
fffff803`451e0c70 488b05c1381800  mov     rax,qword ptr [nt!KiWaitNever (fffff803`45364538)]
fffff803`451e0c77 498b11          mov     rdx,qword ptr [r9]
fffff803`451e0c7a 4833d0          xor     rdx,rax
fffff803`451e0c7d 8bc8            mov     ecx,eax
fffff803`451e0c7f 488d058b250d00  lea     rax,[nt!KdpDataBlockEncoded (fffff803`452b3211)]
fffff803`451e0c86 48d3c2          rol     rdx,cl											<=== HERE
fffff803`451e0c89 4833d0          xor     rdx,rax
fffff803`451e0c8c 480fca          bswap   rdx
fffff803`451e0c8f 4833159a3d1800  xor     rdx,qword ptr [nt!KiWaitAlways (fffff803`45364a30)]
fffff803`451e0c96 4b89140a        mov     qword ptr [r10+r9],rdx

0: kd> db fffff803`451e0c86 L9
fffff803`451e0c86  48 d3 c2 48 33 d0 48 0f-ca                       H..H3.H..
*/
bool findPGkeys(analysisContext_t *context){
	//Looking for nt!KdCopyDataBlock
	const char KdCopyDataBlockPattern[] = { 0x48, 0xD3, 0xC2, 0x48, 0x33, 0xD0, 0x48, 0x0F, 0xCA };
	uint64_t p_KdCopyDataBlock = 0;
	uint64_t i;
	for (i = 0x0; i<context->physicalMemorySize - 4096; i++){
		if (memcmp(context->physicalMemory + i, KdCopyDataBlockPattern, sizeof(KdCopyDataBlockPattern)) == 0){
			p_KdCopyDataBlock = i;
			break;
		}
	}

	//Extract relative address of keys
	uint64_t off_KdDebuggerDataBlock = 0;
	memcpy(&off_KdDebuggerDataBlock, context->physicalMemory + p_KdCopyDataBlock - 37, 4);
	printf("off_KdDebuggerDataBlock : %p\n", off_KdDebuggerDataBlock);
	uint64_t off_KiWaitNever = 0;
	memcpy(&off_KiWaitNever, context->physicalMemory + p_KdCopyDataBlock - 19, 4);
	printf("off_KiWaitNever : %p\n", off_KiWaitNever);
	uint64_t off_KdpDataBlockEncoded = 0;
	memcpy(&off_KdpDataBlockEncoded, context->physicalMemory + p_KdCopyDataBlock - 4, 4);
	printf("off_KdpDataBlockEncoded : %p\n", off_KdpDataBlockEncoded);
	uint64_t off_KiWaitAlways = 0;
	memcpy(&off_KiWaitAlways, context->physicalMemory + p_KdCopyDataBlock + 12, 4);
	printf("off_KiWaitAlways : %p\n", off_KiWaitAlways);

	//Get virtual RIP
	uint64_t v_KdCopyDataBlock = physical_virtual(p_KdCopyDataBlock, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("v_KdCopyDataBlock : %p\n", v_KdCopyDataBlock);

	//Compute virtual adress of keys
	uint64_t v_KdDebuggerDataBlock = v_KdCopyDataBlock - 33 + off_KdDebuggerDataBlock;
	printf("v_KdDebuggerDataBlock : %p\n", v_KdDebuggerDataBlock);
	uint64_t v_KiWaitNever = v_KdCopyDataBlock - 15 + off_KiWaitNever;
	printf("v_KiWaitNever : %p\n", v_KiWaitNever);
	uint64_t v_KdpDataBlockEncoded = v_KdCopyDataBlock + off_KdpDataBlockEncoded;
	printf("v_KdpDataBlockEncoded : %p\n", v_KdpDataBlockEncoded);
	uint64_t v_KiWaitAlways = v_KdCopyDataBlock + 16 + off_KiWaitAlways;
	printf("v_KiWaitAlways : %p\n", v_KiWaitAlways);

	//Get physical address of keys
	uint64_t p_KiWaitNever = virtual_physical(v_KiWaitNever, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("p_KiWaitNever : %p\n", p_KiWaitNever);
	uint64_t p_KiWaitAlways = virtual_physical(v_KiWaitAlways, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("p_KiWaitAlways : %p\n", p_KiWaitAlways);

	//Retrieve keys value
	//..PGKeys_t *keys = (PGKeys_t *)malloc(sizeof(PGKeys_t));
	context->KiWaitNever = BYTESWAP64(read64(p_KiWaitNever, context->physicalMemory));
	printf("keys->KiWaitNever : %p\n", context->KiWaitNever);
	context->KiWaitAlways = BYTESWAP64(read64(p_KiWaitAlways, context->physicalMemory));
	printf("keys->KiWaitAlways : %p\n", context->KiWaitAlways);
	context->KdpDataBlockEncoded = v_KdpDataBlockEncoded;
	printf("keys->KdpDataBlockEncoded : %p\n", context->KdpDataBlockEncoded);
	context->v_KDBG = v_KdDebuggerDataBlock;
	context->p_KDBG = virtual_physical(v_KdDebuggerDataBlock, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);

	
	if (context->curMode == DEBUGGED_IMAGE_TYPE){
		//Retrieve KDBG
		readMMU((char*)&context->KDBG, v_KdDebuggerDataBlock, context->p_DirectoryTableBase, context->physicalMemory, sizeof(_KDDEBUGGER_DATA64));
	}else{
		//Uncipher KDB
		readMMU((char*)&context->encodedKDBG, v_KdDebuggerDataBlock, context->p_DirectoryTableBase, context->physicalMemory, sizeof(_KDDEBUGGER_DATA64));
		for (int i = 0; i < sizeof(KDDEBUGGER_DATA64)/8; i++){
			uint64_t tmpEncodedData = ((uint64_t*)&context->encodedKDBG)[i];
			((uint64_t*)&context->KDBG)[i] = uncipherData(tmpEncodedData, context->KiWaitNever, context->KiWaitAlways, context->KdpDataBlockEncoded);
		}
	}
	printKDBG((KDDEBUGGER_DATA64*)&context->KDBG);

	return true;
}

/*
In my tests, KDBG is always at 0x*************530
*/
bool isDebuggedImage(const unsigned char *memory, uint64_t memSize){
	uint64_t i;
	for (i = 0x0; i < memSize / PAGE_SIZE; i++){
		uint64_t page_base = i*PAGE_SIZE;
		if (memcmp(memory + page_base + 0x530 + 16, "KDBG", 4) == 0){
			return true;
		}
	}
	return false;
}


bool initialeAnalysis(analysisContext_t *context){
	if (context->curMode == AUTO_IMAGE_TYPE){
		if (isDebuggedImage(context->physicalMemory, context->physicalMemorySize) == true){
			printf("[INFO] Debugged Image File !\n");
			context->curMode = DEBUGGED_IMAGE_TYPE;
		}else{
			printf("[INFO] Stock Image File !\n");
			context->curMode = STOCK_IMAGE_TYPE;
		}
	}
	context->p_DirectoryTableBase = findDTB(context->physicalMemory, context->physicalMemorySize);
	printf("p_DirectoryTableBase : 0x%p\n", context->p_DirectoryTableBase);
	context->p_KPCR = findKPCR(0, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("p_KPCR : %p\n", context->p_KPCR);
	context->v_KPCR = BYTESWAP64(read64(context->p_KPCR + 0x18, context->physicalMemory));
	printf("v_KPCR : %p\n", context->v_KPCR);
	context->p_KPRCB = context->p_KPCR + 0x180;
	printf("p_KPRCB : %p\n", context->p_KPRCB);
	context->v_KPRCB = BYTESWAP64(read64(context->p_KPCR + 0x20, context->physicalMemory));
	printf("v_KPRCB : %p\n", context->v_KPRCB);
	context->v_CurrentThread = BYTESWAP64(read64(context->p_KPRCB + 8, context->physicalMemory));
	printf("v_CurrentThread : 0x%p !\n", context->v_CurrentThread);


	findPGkeys(context); //TODO: rename it to findRAWMODEKDBG....
	//context->p_KDBG = context->KDBGInformation->p_KDBG;
	//context->v_KDBG = context->KDBGInformation->v_KDBG;
	printf("v_KDBG : %p\n", context->v_KDBG);
	context->v_KernBase = context->KDBG.KernBase;
	printf("v_KernBase : %p\n", context->v_KernBase);
	context->v_PsLoadedModuleList = context->KDBG.PsLoadedModuleList;
	printf("v_PsLoadedModuleList : %p\n", context->v_PsLoadedModuleList);

	context->v_DbgBreakPointWithStatus = context->KDBG.BreakpointWithStatus;
	printf("v_DbgBreakPointWithStatus : %p\n", context->v_DbgBreakPointWithStatus);

	context->v_curRIP = context->v_DbgBreakPointWithStatus; //Physical dump...
	printf("v_curRIP : %p\n", context->v_curRIP);

	context->p_curRIP = virtual_physical(context->v_curRIP, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("p_curRIP : %p\n", context->p_curRIP);

	context->p_DebuggerDataList = findDebuggerDataList(context->v_KDBG, context->physicalMemory, context->physicalMemorySize);
	printf("p_DebuggerDataList : %p\n", context->p_DebuggerDataList);
	context->v_DebuggerDataList = physical_virtual(context->p_DebuggerDataList, context->p_DirectoryTableBase, context->physicalMemory, context->physicalMemorySize);
	printf("v_DebuggerDataList : %p\n", context->v_DebuggerDataList);

	return true;
}