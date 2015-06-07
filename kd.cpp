#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "kd.h"
#include "mmu.h"
#include "utils.h"
#include "kdserver.h"

uint32_t ChecksumKD(kd_packet_t *pkt){
	uint32_t checksum = 0;
	for (int i = 0; i<pkt->length; i++){
		checksum = checksum + pkt->data[i];
	}
	return checksum;
}


int ReadKDPipe(HANDLE hPipe, kd_packet_t *pktBuffer){
	DWORD numBytesRead = 0;
	BOOL result;
	UINT8 firstCMD = 0x00;
	do{
		firstCMD = Get8Pipe(hPipe);
	} while (firstCMD != 0x69 && firstCMD != 0x30 && firstCMD != 0x62);

	if (firstCMD == 0x62){ //Fast-Break !!!
		return FASTBREAK_PKT; //TODO: return FAST-BREAK !
	}
	UINT32 leader = (firstCMD << 24) | (Get16Pipe(hPipe) << 8) | Get8Pipe(hPipe);
	if (leader == 0x69696969
		|| leader == 0x30303030){
		UINT16 type = Get16Pipe(hPipe);
		UINT16 length = Get16Pipe(hPipe);
		UINT32 id = Get32Pipe(hPipe);
		UINT32 checksum = Get32Pipe(hPipe);

		pktBuffer->leader = leader;
		pktBuffer->type = type;
		pktBuffer->length = length;
		pktBuffer->id = id;
		pktBuffer->checksum = checksum;

		//TODO: function !
		UINT16 bytesToRead = length;
		UINT16 bytesAlreadyRead = 0;
		while (bytesToRead > 0){
			//printf("bytesToRead %d\n", bytesToRead);
			result = ReadFile(hPipe, pktBuffer->data + bytesAlreadyRead, bytesToRead, &numBytesRead, NULL);
			bytesToRead = bytesToRead - numBytesRead;
			bytesAlreadyRead = bytesAlreadyRead + numBytesRead;
			//printf("%d/%d\n", bytesAlreadyRead, length);
		}

		//END_OF_DATA
		if (length > 0){
			char endOfData;
			ReadFile(hPipe, &endOfData, 1, NULL, NULL);
		}

		return KD_PKT;
	}else{
		UINT16 type = Get16Pipe(hPipe);
		printf("Unknown Leader %08x\n", leader);
		printf("type: %04x\n", type);
		//system("pause");
	}
	return ERR_PKT;
}

DWORD WriteKDPipe(HANDLE hPipe, kd_packet_t *pkt){
	DWORD numBytesWritten = 0;
	BOOL result = WriteFile(hPipe, pkt, pkt->length + 16, &numBytesWritten, NULL);

	//END_OF_DATA
	if (pkt->length > 0){
		char endOfData = 0xAA;
		WriteFile(hPipe, &endOfData, 1, NULL, NULL);
	}

	FlushFileBuffers(hPipe);

	return numBytesWritten;
}


bool ParseKDPkt(kd_packet_t* pkt){
	printf("------------RAW--------------\n");
	dumpHexData((char*)pkt, pkt->length + 16);
	printf("-----------------------------\n");
	printf("---------KD_HEADER-----------\n");
	printf("Leader: %08x\n", pkt->leader);
	printf("PacketType: %04x\n", pkt->type);
	printf("DataSize: %d\n", pkt->length);
	printf("PacketID: %08x\n", pkt->id);
	printf("Checksum: %08x\n", pkt->checksum);
	printf("Checksum(check): %08x\n", ChecksumKD(pkt));
	if (pkt->length > 0){
		printf("\t---------KD_CONTENT-----------\n");
		printf("\tApiNumber %08x\n", pkt->ApiNumber);
		if (pkt->type == KD_PACKET_TYPE_MANIP){
			printf("\t\t---------KD_MANIP-----------\n");
			printf("\t\tProcessorLevel: %04x\n", pkt->ManipulateState64.ProcessorLevel);
			printf("\t\tProcessor: %04x\n", pkt->ManipulateState64.Processor);
			printf("\t\tReturnStatus: %08x\n", pkt->ManipulateState64.ReturnStatus);
			dumpHexData((char*)pkt->ManipulateState64.data, pkt->length - 12);
			printf("\t\t----------------------------\n");
		}
		switch (pkt->ApiNumber){
		case DbgKdGetVersionApi:
			printf("\t[DbgKdGetVersionApi]\n");
			printf("\tMajorVersion %04x\n", pkt->ManipulateState64.GetVersion.MajorVersion);
			printf("\tMinorVersion %04x\n", pkt->ManipulateState64.GetVersion.MinorVersion);
			printf("\tProtocolVersion %04x\n", pkt->ManipulateState64.GetVersion.ProtocolVersion);
			printf("\tFlags %04x\n", pkt->ManipulateState64.GetVersion.Flags);
			printf("\tMachineType %04x\n", pkt->ManipulateState64.GetVersion.MachineType);
			printf("\tMaxPacketType %02x\n", pkt->ManipulateState64.GetVersion.MaxPacketType);
			printf("\tMaxStateChange %02x\n", pkt->ManipulateState64.GetVersion.MaxStateChange);
			printf("\tMaxManipulate %02x\n", pkt->ManipulateState64.GetVersion.MaxManipulate);
			printf("\tSimulation %02x\n", pkt->ManipulateState64.GetVersion.Simulation);
			printf("\tUnknown1 %04x\n", pkt->ManipulateState64.GetVersion.Unknown1);
			printf("\tKernelImageBase %p\n", pkt->ManipulateState64.GetVersion.KernelImageBase);
			printf("\tPsLoadedModuleList %p\n", pkt->ManipulateState64.GetVersion.PsLoadedModuleList);
			printf("\tDebuggerDataList %p\n", pkt->ManipulateState64.GetVersion.DebuggerDataList);
			printf("\tUnknown2 %p\n", pkt->ManipulateState64.GetVersion.Unknown2);
			printf("\tUnknown3 %p\n", pkt->ManipulateState64.GetVersion.Unknown3);
			break;
		case DbgKdReadVirtualMemoryApi:
			printf("\t[DbgKdReadVirtualMemoryApi]\n");
			printf("\tTargetBaseAddress %p\n", pkt->ManipulateState64.ReadMemory.TargetBaseAddress);
			printf("\tTransferCount %08x\n", pkt->ManipulateState64.ReadMemory.TransferCount);
			printf("\tActualBytesRead %08x\n", pkt->ManipulateState64.ReadMemory.ActualBytesRead);
			//printf("\tUnknown1 %p\n", pkt->ManipulateState64.ReadMemory.Unknown1);
			//printf("\tUnknown2 %p\n", pkt->ManipulateState64.ReadMemory.Unknown2);
			//printf("\tUnknown3 %p\n", pkt->ManipulateState64.ReadMemory.Unknown3);
			if (pkt->length > 56){
				printHexData((char*)pkt->ManipulateState64.ReadMemory.Data, pkt->ManipulateState64.ReadMemory.TransferCount);
			}
			break;
		case DbgKdReadPhysicalMemoryApi:
			printf("\t[DbgKdReadPhysicalMemoryApi]\n");
			printf("\tTargetBaseAddress %p\n", pkt->ManipulateState64.ReadMemory.TargetBaseAddress);
			printf("\tTransferCount %08x\n", pkt->ManipulateState64.ReadMemory.TransferCount);
			printf("\tActualBytesRead %08x\n", pkt->ManipulateState64.ReadMemory.ActualBytesRead);
			//printf("\tUnknown1 %p\n", pkt->ManipulateState64.ReadMemory.Unknown1);
			//printf("\tUnknown2 %p\n", pkt->ManipulateState64.ReadMemory.Unknown2);
			//printf("\tUnknown3 %p\n", pkt->ManipulateState64.ReadMemory.Unknown3);
			if (pkt->length > 56){
				printHexData((char*)pkt->ManipulateState64.ReadMemory.Data, pkt->ManipulateState64.ReadMemory.TransferCount);
			}
			break;
		case DbgKdReadControlSpaceApi:
			printf("\t[DbgKdReadControlSpaceApi]\n");
			//TODO: 0 @KPCR, 1 @KPRCB, 2 @SpecialReagister, 3 @KTHREAD
			printf("\tTargetBaseAddress(index) %p\n", pkt->ManipulateState64.ReadMemory.TargetBaseAddress);
			printf("\tTransferCount %08x\n", pkt->ManipulateState64.ReadMemory.TransferCount);
			printf("\tActualBytesRead %08x\n", pkt->ManipulateState64.ReadMemory.ActualBytesRead);
			//printf("\tUnknown1 %p\n", pkt->ManipulateState64.ReadMemory.Unknown1);
			//printf("\tUnknown2 %p\n", pkt->ManipulateState64.ReadMemory.Unknown2);
			//printf("\tUnknown3 %p\n", pkt->ManipulateState64.ReadMemory.Unknown3);
			if (pkt->length > 56){
				printHexData((char*)pkt->ManipulateState64.ReadMemory.Data, pkt->ManipulateState64.ReadMemory.TransferCount);
			}
			break;
		case DbgKdWriteControlSpaceApi:
			printf("\t[DbgKdWriteControlSpaceApi]\n");
			printf("\tTargetBaseAddress(index) %p\n", pkt->ManipulateState64.WriteMemory.TargetBaseAddress);
			printf("\tTransferCount %08x\n", pkt->ManipulateState64.WriteMemory.TransferCount);
			printf("\tActualBytesWritten %08x\n", pkt->ManipulateState64.WriteMemory.ActualBytesWritten);
			switch (pkt->ManipulateState64.ReadMemory.TargetBaseAddress){
			case 0: //@v_KPCR
				break;
			case 1: //@v_KPRCB
				break;
			case 2:{ //@SpecialRegisters
				KSPECIAL_REGISTERS64 *tmpSpecialRegisters = (KSPECIAL_REGISTERS64*)pkt->ManipulateState64.WriteMemory.Data;
				printf("\tKernelDr0 : 0x%p\n", tmpSpecialRegisters->KernelDr0);
				printf("\tKernelDr1 : 0x%p\n", tmpSpecialRegisters->KernelDr1);
				printf("\tKernelDr2 : 0x%p\n", tmpSpecialRegisters->KernelDr2);
				printf("\tKernelDr3 : 0x%p\n", tmpSpecialRegisters->KernelDr3);
				printf("\tKernelDr6 : 0x%p\n", tmpSpecialRegisters->KernelDr6);
				printf("\tKernelDr7 : 0x%p\n", tmpSpecialRegisters->KernelDr7);
				break;
			}
			case 3: //@v_KTHREAD
				break;
			default:
				break;
			};
			break;
		case DbgKdRestoreBreakPointApi:
			printf("\t[DbgKdRestoreBreakPointApi]\n");
			printf("\tBreakPointHandle %08x\n", pkt->ManipulateState64.RestoreBreakPoint.BreakPointHandle);
			break;
		case DbgKdClearAllInternalBreakpointsApi:
			printf("\t[DbgKdClearAllInternalBreakpointsApi]\n");
			break;
		case DbgKdGetRegister:
			printf("\t[DbgKdGetRegister]\n");

			for (int i = 0; i < 12; i++){
				printf("pkt->ManipulateState64.GetRegisters.u[%d] = 0x%p;\n", i, pkt->ManipulateState64.GetRegisters.u[i]);
			}
			if (pkt->length > 56){
				printf("SegCs %04x\n", pkt->ManipulateState64.GetRegisters.SegCs);
				printf("SegDs %04x\n", pkt->ManipulateState64.GetRegisters.SegDs);
				printf("SegEs %04x\n", pkt->ManipulateState64.GetRegisters.SegEs);
				printf("SegFs %04x\n", pkt->ManipulateState64.GetRegisters.SegFs);
				printf("SegGs %04x\n", pkt->ManipulateState64.GetRegisters.SegGs);
				printf("SegSs %04x\n", pkt->ManipulateState64.GetRegisters.SegSs);
				printf("EFlags %08x\n", pkt->ManipulateState64.GetRegisters.EFlags);

				printf("Dr0 %p\n", pkt->ManipulateState64.GetRegisters.Dr0);
				printf("Dr1 %p\n", pkt->ManipulateState64.GetRegisters.Dr1);
				printf("Dr2 %p\n", pkt->ManipulateState64.GetRegisters.Dr2);
				printf("Dr3 %p\n", pkt->ManipulateState64.GetRegisters.Dr3);
				printf("Dr6 %p\n", pkt->ManipulateState64.GetRegisters.Dr6);
				printf("Dr7 %p\n", pkt->ManipulateState64.GetRegisters.Dr7);

				printf("Rax %p\n", pkt->ManipulateState64.GetRegisters.Rax);
				printf("Rcx %p\n", pkt->ManipulateState64.GetRegisters.Rcx);
				printf("Rdx %p\n", pkt->ManipulateState64.GetRegisters.Rdx);
				printf("Rbx %p\n", pkt->ManipulateState64.GetRegisters.Rbx);
				printf("Rsp %p\n", pkt->ManipulateState64.GetRegisters.Rsp);
				printf("Rbp %p\n", pkt->ManipulateState64.GetRegisters.Rbp);
				printf("Rsi %p\n", pkt->ManipulateState64.GetRegisters.Rsi);
				printf("Rdi %p\n", pkt->ManipulateState64.GetRegisters.Rdi);
				printf("R8 %p\n", pkt->ManipulateState64.GetRegisters.R8);
				printf("R9 %p\n", pkt->ManipulateState64.GetRegisters.R9);
				printf("R10 %p\n", pkt->ManipulateState64.GetRegisters.R10);
				printf("R11 %p\n", pkt->ManipulateState64.GetRegisters.R11);
				printf("R12 %p\n", pkt->ManipulateState64.GetRegisters.R12);
				printf("R13 %p\n", pkt->ManipulateState64.GetRegisters.R13);
				printf("R14 %p\n", pkt->ManipulateState64.GetRegisters.R14);
				printf("R15 %p\n", pkt->ManipulateState64.GetRegisters.R15);

				printf("Rip %p\n", pkt->ManipulateState64.GetRegisters.Rip);

				for (int i = 0; i < 122; i++){
					printf("tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[%d] = 0x%p;\n", i, pkt->ManipulateState64.GetRegisters.DATA[i]);
				}
			}
			break;
		case DbgKdSetContextApi: //Go !
			printf("\t[DbgKdSetContextApi]\n");
			//TODO !! Copy KiProcessorBlock[State->Processor]->ProcessorState.ContextFrame;
			break;
		case DbgKdContinueApi:
			printf("\t[DbgKdContinueApi]\n");
			break;
		case DbgKdContinueApi2: //Go !
			printf("\t[DbgKdContinueApi2]\n");
			//TODO
			printf("\tNTSTATUS %08\n", pkt->ManipulateState64.Continue2.ContinueStatus);
			printf("\tTraceFlag %08\n", pkt->ManipulateState64.Continue2.ControlSet.TraceFlag);
			printf("\tDr7 %p\n", pkt->ManipulateState64.Continue2.ControlSet.Dr7);
			printf("\tCurrentSymbolStart %p\n", pkt->ManipulateState64.Continue2.ControlSet.CurrentSymbolStart);
			printf("\tCurrentSymbolEnd %p\n", pkt->ManipulateState64.Continue2.ControlSet.CurrentSymbolEnd);
			break;

			//VM->Windbg
		case DbgKdExceptionStateChange:
			printf("\t[DbgKdExceptionStateChange]\n");
			printf("\tNewState %08x\n", pkt->StateChange.NewState);
			printf("\tProcessorLevel %04x\n", pkt->StateChange.ProcessorLevel);
			printf("\tProcessor %04x\n", pkt->StateChange.Processor);
			printf("\tNumberProcessors %08x\n", pkt->StateChange.NumberProcessors);
			printf("\tThread %p\n", pkt->StateChange.Thread);
			printf("\tProgramCounter %p\n", pkt->StateChange.ProgramCounter);

			//TODO: printExceptionRecord			
			printf("ExceptionCode %08x\n", pkt->StateChange.Exception.ExceptionRecord.ExceptionCode);
			printf("ExceptionFlags %08x\n", pkt->StateChange.Exception.ExceptionRecord.ExceptionFlags);
			printf("ExceptionRecord %016lx\n", pkt->StateChange.Exception.ExceptionRecord.ExceptionRecord);
			printf("ExceptionAddress %016lx\n", pkt->StateChange.Exception.ExceptionRecord.ExceptionAddress);
			printf("NumberParameters %08x\n", pkt->StateChange.Exception.ExceptionRecord.NumberParameters);
			printf("u1 %08x\n", pkt->StateChange.Exception.ExceptionRecord.u1);
			for (int i = 0; i<EXCEPTION_MAXIMUM_PARAMETERS; i++){
				printf("ExceptionInformation[%d] %016lx\n", i, pkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[i]);
			}
			printf("FirstChance %08x\n", pkt->StateChange.Exception.FirstChance);


			printf("\tDR6 %016lx\n", pkt->StateChange.ControlReport.Dr6);
			printf("\tDR7 %016lx\n", pkt->StateChange.ControlReport.Dr7);
			printf("\tEFlags %08x\n", pkt->StateChange.ControlReport.EFlags);
			printf("\tInstructionCount %04x\n", pkt->StateChange.ControlReport.InstructionCount);
			printf("\tReportFlags %04x\n", pkt->StateChange.ControlReport.ReportFlags);
			for (int i = 0; i<min(DBGKD_MAXSTREAM, pkt->StateChange.ControlReport.InstructionCount); i++){
				printf("\tInstructionStream[%d] %02x\n", i, pkt->StateChange.ControlReport.InstructionStream[i]);
			}
			printf("\tSegCs %04x\n", pkt->StateChange.ControlReport.SegCs);
			printf("\tSegDs %04x\n", pkt->StateChange.ControlReport.SegDs);
			printf("\tSegEs %04x\n", pkt->StateChange.ControlReport.SegEs);
			printf("\tSegFs %04x\n", pkt->StateChange.ControlReport.SegFs);
			break;
		case DbgKdLoadSymbolsStateChange:
			printf("\t[DbgKdLoadSymbolsStateChange]\n");
			//THE FUCK ?
			break;
		case DbgKdSwitchProcessor:
			printf("\t[DbgKdSwitchProcessor]\n");
			break;
		case DbgKdQueryMemoryApi:
			printf("\t[DbgKdQueryMemoryApi]\n");
			printf("\tAddress 0x%p\n", pkt->ManipulateState64.QueryMemory.Address);
			printf("\tReserved 0x%p\n", pkt->ManipulateState64.QueryMemory.Reserved);
			printf("\tAddressSpace 0x%08X\n", pkt->ManipulateState64.QueryMemory.AddressSpace);
			printf("\tFlags 0x%08X\n", pkt->ManipulateState64.QueryMemory.Flags);
			break;
		default: //Stop ALL !
			printf("\t[UNKNOWN]\n");
			//stopKDServer();
			//printHexData((char*)pkt->data, pkt->length);
			//system("pause");
		}
		printf("\t---------KD_CONTENT-----------\n");
	}
	printf("---------KD_HEADER-----------\n");
	printf("\n\n");
	return true;
}