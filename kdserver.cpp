#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "kdserver.h"
#include "mmu.h"
#include "kd.h"
#include "utils.h"
#include "dissectors.h"
#include "FDP.h"


//Windbg->Proxy
HANDLE DBGPipe; 
UINT8 serverRunning;
analysisContext_t *curContext; //TODO: remove this !



BOOL sendKDPkt(kd_packet_t* toSendKDPkt){
	toSendKDPkt->checksum = ChecksumKD(toSendKDPkt);
	//ParseKDPkt(toSendKDPkt);
	DWORD numBytesWritten = WriteKDPipe(DBGPipe, toSendKDPkt);
	printf("[FAKEVM->Windbg] Write to Windbg : %d\n", numBytesWritten);
	return true;
}



uint64_t WDBG_getRegister(analysisContext_t *context, uint8_t registerId ){
	if (context->curMode == STOCK_VBOX_TYPE){
		return FDP_readRegister(context->toVMPipe, registerId);
	}

	if (registerId == RIP_REGISTER){
		return context->v_DbgBreakPointWithStatus;
	}
	return 0;
}

bool WDBG_resume(analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){
		return FDP_resume(context->toVMPipe);
	}
	return true;
}

bool WDBG_pause(analysisContext_t *context){
	if (context->curMode == STOCK_VBOX_TYPE){
		return FDP_pause(context->toVMPipe);
	}
	return true;
}

//
BOOL handleBreakPkt(){
	printf("[BREAK]\n");
	WDBG_pause(curContext);

	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	//Create ExceptionStateChange Pkt
	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_STATE_CHANGE;
	tmpKDRespPkt->length = 240;
	tmpKDRespPkt->id = 0x80800800;
	tmpKDRespPkt->StateChange.ApiNumber = DbgKdExceptionStateChange;
	tmpKDRespPkt->StateChange.NewState = 0x00000006;
	tmpKDRespPkt->StateChange.ProcessorLevel = 0x0002;
	tmpKDRespPkt->StateChange.Processor = 0x0000;
	tmpKDRespPkt->StateChange.NumberProcessors = 0x0000;
	tmpKDRespPkt->StateChange.Thread = curContext->v_CurrentThread;
	tmpKDRespPkt->StateChange.ProgramCounter = WDBG_getRegister(curContext, RIP_REGISTER);

	//Works without this... TODO:
	/*tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionAddress = 0x0000000045158890;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.NumberParameters = 0x00000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.u1 = 0xffff4e51;
	tmpKDRespPkt->StateChange.Exception.FirstChance = 0x00000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[0] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[1] = 0x000000004579b500;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[2] = 0x0000000046abfd98;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[3] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[4] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[5] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[6] = 0x000000004579aca1;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[7] = 0x0000000046abfb70;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[8] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[9] = 0x0000000000000712;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[10] = 0x0000000000000320;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[11] = 0x0000000046abfaf0;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[12] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[13] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[14] = 0x000000004503d8ee;*/

	//tmpKDRespPkt->StateChange.ControlReport.Dr6 = 0x00000000ffff0ff0;
	tmpKDRespPkt->StateChange.ControlReport.Dr6 = WDBG_getRegister(curContext, DR6_REGISTER);
	//tmpKDRespPkt->StateChange.ControlReport.Dr7 = 0x0000000000000400;
	tmpKDRespPkt->StateChange.ControlReport.Dr7 = WDBG_getRegister(curContext, DR7_REGISTER);
	//tmpKDRespPkt->StateChange.ControlReport.EFlags = 0x00000286;
	tmpKDRespPkt->StateChange.ControlReport.EFlags = WDBG_getRegister(curContext, RFLAGS_REGISTER);
	tmpKDRespPkt->StateChange.ControlReport.InstructionCount = 0x0010;
	for (int i = 0; i < tmpKDRespPkt->StateChange.ControlReport.InstructionCount; i++){
		tmpKDRespPkt->StateChange.ControlReport.InstructionStream[i] = readPhysical8(curContext->p_curRIP + i, curContext);
	}
	tmpKDRespPkt->StateChange.ControlReport.ReportFlags = 0x0003;
	/*tmpKDRespPkt->StateChange.ControlReport.SegCs = 0x0010;
	tmpKDRespPkt->StateChange.ControlReport.SegDs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegEs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegFs = 0x0053;*/
	tmpKDRespPkt->StateChange.ControlReport.SegCs = WDBG_getRegister(curContext, CS_REGISTER);
	tmpKDRespPkt->StateChange.ControlReport.SegDs = WDBG_getRegister(curContext, DS_REGISTER);
	tmpKDRespPkt->StateChange.ControlReport.SegEs = WDBG_getRegister(curContext, ES_REGISTER);
	tmpKDRespPkt->StateChange.ControlReport.SegFs = WDBG_getRegister(curContext, FS_REGISTER);


	sendKDPkt(tmpKDRespPkt);
	return true;
}

BOOL handleResetPkt(){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	printf("KD_PACKET_TYPE_RESET\n");
	//TODO: Reset all server state !
	tmpKDRespPkt->leader = KD_CONTROL_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_RESET;
	tmpKDRespPkt->id = 0xfd772d60;
	tmpKDRespPkt->checksum = ChecksumKD(tmpKDRespPkt);

	sendKDPkt(tmpKDRespPkt);
	return true;
}

BOOL ackKDPkt(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	//TODO: ACK Function!
	tmpKDRespPkt->leader = KD_CONTROL_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_ACK;
	tmpKDRespPkt->length = 0x00;
	tmpKDRespPkt->id = tmpKDPkt->id;

	sendKDPkt(tmpKDRespPkt);
	return true;
}
BOOL handleDbgKdGetVersionApiPkt(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 56;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ManipulateState64.ApiNumber = DbgKdGetVersionApi;
	tmpKDRespPkt->ManipulateState64.GetVersion.MajorVersion = 0x000f;
	tmpKDRespPkt->ManipulateState64.GetVersion.MinorVersion = 0x2580;
	tmpKDRespPkt->ManipulateState64.GetVersion.ProtocolVersion = 0x0206;
	tmpKDRespPkt->ManipulateState64.GetVersion.Flags = 0x0007;
	tmpKDRespPkt->ManipulateState64.GetVersion.MachineType = 0x8664;
	tmpKDRespPkt->ManipulateState64.GetVersion.MaxPacketType = 0x0c;
	tmpKDRespPkt->ManipulateState64.GetVersion.MaxStateChange = 0x03;
	tmpKDRespPkt->ManipulateState64.GetVersion.MaxManipulate = 0x31;
	tmpKDRespPkt->ManipulateState64.GetVersion.Simulation = 0x00;
	tmpKDRespPkt->ManipulateState64.GetVersion.Unknown1 = 0x0000;
	tmpKDRespPkt->ManipulateState64.GetVersion.KernelImageBase = curContext->v_KernBase;
	tmpKDRespPkt->ManipulateState64.GetVersion.PsLoadedModuleList = curContext->v_PsLoadedModuleList;
	tmpKDRespPkt->ManipulateState64.GetVersion.DebuggerDataList = curContext->v_DebuggerDataList;
	//tmpKDRespPkt->ManipulateState64.GetVersion.Unknown2 = 0x00000000FDFDFDFD;
	//tmpKDRespPkt->ManipulateState64.GetVersion.Unknown3 = 0x0000000000000000;

	sendKDPkt(tmpKDRespPkt);

	return true;
}

BOOL handleDbgKdReadVirtualMemoryApiPkt(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 56 + tmpKDPkt->ManipulateState64.ReadMemory.TransferCount;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ManipulateState64.ApiNumber = DbgKdReadVirtualMemoryApi;
	tmpKDRespPkt->ManipulateState64.ReadMemory.TargetBaseAddress = tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress;
	tmpKDRespPkt->ManipulateState64.ReadMemory.TransferCount = tmpKDPkt->ManipulateState64.ReadMemory.TransferCount;
	tmpKDRespPkt->ManipulateState64.ReadMemory.ActualBytesRead = tmpKDPkt->ManipulateState64.ReadMemory.TransferCount;
	//Lot of possibilities here... 
	//Windbg read @v_KDBG or @v_KDBG+sizeof(DBGKD_DEBUG_DATA_HEADER64)
	//But what do I have to print when user want to read v_KDBG ? (Ciphered or Unciphered) ?
	if (tmpKDRespPkt->ManipulateState64.ReadMemory.TargetBaseAddress == curContext->v_KDBG
		|| tmpKDRespPkt->ManipulateState64.ReadMemory.TargetBaseAddress == curContext->v_KDBG + sizeof(DBGKD_DEBUG_DATA_HEADER64)){ //TODO: check overflow !
		uint64_t offInKDBG = tmpKDRespPkt->ManipulateState64.ReadMemory.TargetBaseAddress - curContext->v_KDBG;
		memcpy((char*)tmpKDRespPkt->ManipulateState64.ReadMemory.Data, ((char*)(&curContext->KDBG))+offInKDBG, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount);
	}else{
		readMMU(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount, tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress, curContext);
	}
	sendKDPkt(tmpKDRespPkt);

	return true;
}

BOOL handleDbgKdReadControlSpaceApi(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 56 + 8;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ManipulateState64.ApiNumber = DbgKdReadControlSpaceApi;
	tmpKDRespPkt->ManipulateState64.ReadMemory.TargetBaseAddress = tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress;
	tmpKDRespPkt->ManipulateState64.ReadMemory.TransferCount = tmpKDPkt->ManipulateState64.ReadMemory.TransferCount;
	tmpKDRespPkt->ManipulateState64.ReadMemory.ActualBytesRead = tmpKDPkt->ManipulateState64.ReadMemory.TransferCount;
	switch (tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress){
	case 0: //@KPCR
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &curContext->v_KPCR, 8);
		break;
	case 1: //@KPRCB
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &curContext->v_KPRCB, 8);
		break;
	case 2: //@SpecialReagister
		//readPhysical(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount, curContext->p_KPRCB + 0x40 + 0x00, curContext);
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &curContext->SpecialRegister, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount);
		break;
	case 3: //@KTHREAD
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &curContext->v_CurrentThread, 8);
		break;
	default:
		printf("TODO !!!!\n");
		ParseKDPkt(tmpKDPkt);
		system("pause");
	}
	sendKDPkt(tmpKDRespPkt);

	return true;
}


BOOL handleDbgKdRestoreBreakPointApi(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 56;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ManipulateState64.ApiNumber = DbgKdRestoreBreakPointApi;
	tmpKDRespPkt->ManipulateState64.RestoreBreakPoint.BreakPointHandle = tmpKDPkt->ManipulateState64.RestoreBreakPoint.BreakPointHandle;

	sendKDPkt(tmpKDRespPkt);

	return true;
}

BOOL handleDbgKdGetRegister(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 1288;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ManipulateState64.ApiNumber = DbgKdGetRegister;
	//TODO: What those values are ?
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[0] = tmpKDPkt->ManipulateState64.GetRegisters.u[0];
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[1] = tmpKDPkt->ManipulateState64.GetRegisters.u[1] + 0x4D0;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[2] = tmpKDPkt->ManipulateState64.GetRegisters.u[2];
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[3] = tmpKDPkt->ManipulateState64.GetRegisters.u[3];
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[4] = tmpKDPkt->ManipulateState64.GetRegisters.u[4];
	//What is this ?
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[5] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[6] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[7] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[8] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[9] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[10] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[11] = 0x00001F800010001F;

	tmpKDRespPkt->ManipulateState64.GetRegisters.SegCs = WDBG_getRegister(curContext, CS_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegDs = WDBG_getRegister(curContext, DS_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegEs = WDBG_getRegister(curContext, ES_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegFs = WDBG_getRegister(curContext, FS_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegGs = WDBG_getRegister(curContext, GS_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegSs = WDBG_getRegister(curContext, SS_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rip = WDBG_getRegister(curContext, RIP_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rbp = WDBG_getRegister(curContext, RBP_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rsp = WDBG_getRegister(curContext, RSP_REGISTER);

	tmpKDRespPkt->ManipulateState64.GetRegisters.Rax = WDBG_getRegister(curContext, RAX_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rbx = WDBG_getRegister(curContext, RBX_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rcx = WDBG_getRegister(curContext, RCX_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rdx = WDBG_getRegister(curContext, RDX_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rsi = WDBG_getRegister(curContext, RSI_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rdi = WDBG_getRegister(curContext, RDI_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R8 = WDBG_getRegister(curContext, R8_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R9 = WDBG_getRegister(curContext, R9_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R10 = WDBG_getRegister(curContext, R10_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R11 = WDBG_getRegister(curContext, R11_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R12 = WDBG_getRegister(curContext, R12_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R13 = WDBG_getRegister(curContext, R13_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R14 = WDBG_getRegister(curContext, R14_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.R15 = WDBG_getRegister(curContext, R15_REGISTER);

	tmpKDRespPkt->ManipulateState64.GetRegisters.EFlags = WDBG_getRegister(curContext, RFLAGS_REGISTER);

	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr0 = WDBG_getRegister(curContext, DR0_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr1 = WDBG_getRegister(curContext, DR1_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr2 = WDBG_getRegister(curContext, DR2_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr3 = WDBG_getRegister(curContext, DR3_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr6 = WDBG_getRegister(curContext, DR6_REGISTER);
	tmpKDRespPkt->ManipulateState64.GetRegisters.Dr7 = WDBG_getRegister(curContext, DR7_REGISTER);

	//Works without this... //TODO: !
	/*tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[0] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[1] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[2] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[3] = 0x0000000000001F80;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[4] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[5] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[6] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[7] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[8] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[9] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[10] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[11] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[12] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[13] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[14] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[15] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[16] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[17] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[18] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[19] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[20] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[21] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[22] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[23] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[24] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[25] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[26] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[27] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[28] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[29] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[30] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[31] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[32] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[33] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[34] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[35] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[36] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[37] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[38] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[39] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[40] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[41] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[42] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[43] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[44] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[45] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[46] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[47] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[48] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[49] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[50] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[51] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[52] = 0xFFFFF80346ABF5C0;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[53] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[54] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[55] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[56] = 0xFFFFF80346ABF540;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[57] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[58] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[59] = 0xFFFFF803450DBF38; //nt!KiIpiProcessRequests+0x208
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[60] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[61] = 0xFFFFFFF600000002;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[62] = 0x00000001FFFFFFFF;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[63] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[64] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[65] = 0xFFFFF8034462602B; //kdcom!ReadLsr+0x63
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[66] = 0xFFFF91341EDF5A4F;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[67] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[68] = 0x0000000000000200;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[69] = 0x0000000000000001;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[70] = 0x000000000000000B;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[71] = 0x0000000000000001;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[72] = 0xFFFFF80300000002;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[73] = 0xFFFFF8034515822C; //nt!KiIpiInterruptSubDispatch+0x7c
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[74] = 0x0000000000000201;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[75] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[76] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[77] = 0xFFFFF803452E2460; //nt!KdLogBuffer
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[78] = 0x0000000000000008;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[79] = 0xFFFFF80345157FFF; //nt!KiIpiInterrupt+0xff
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[80] = 0xFFFFF80345304100; //nt!KiInitialPCR+0x100
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[81] = 0xFFFFF80346ABF630;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[82] = 0xFFFFF80346ABF5F0;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[83] = 0xFFFFF8034515800C; //nt!KiIpiInterrupt+0x10c
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[84] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[85] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[86] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[87] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[88] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[89] = 0x00001F8000000D00;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[90] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[91] = 0xB652A7D704140000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[92] = 0xFFFFF80346ABF7C8;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[93] = 0xFFFFF80346ABF820;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[94] = 0x00000000000000D2;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[95] = 0xFFFFF8034579B5B0; //hal!HalpApicRequestInterrupt
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[96] = 0xFFFFF80346ABFA78;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[97] = 0xFFFFF8034579B69A; //hal!HalpApicRequestInterrupt+0xea
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[98] = 0x447CE32730336ED4;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[99] = 0x0861C852B651E09D;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[100] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[101] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[102] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[103] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[104] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[105] = 0xFFFF4E51E17CF274;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[106] = 0xFFFFF80345304180; //nt!KiInitialPCR+0x180
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[107] = 0x0000000000000200;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[108] = 0x0000000000000001;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[109] = 0x000000000000000B;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[110] = 0x0000000000000001;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[111] = 0xFFFFF8034579ACA1; //hal!HalRequestClockInterrupt+0x240
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[112] = 0xFFFFF80346ABF7A0;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[113] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[114] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[115] = 0xFFFFF8034509561F; //nt!RtlGetExtendedContextLength+0x1f
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[116] = 0xFFFFF80346ABF720;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[117] = 0xFFFFF8034579B69A; //hal!HalpApicRequestInterrupt+0xea
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[118] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[119] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[120] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.DATA[121] = 0x0000000000000000;*/

	sendKDPkt(tmpKDRespPkt);

	return true;
}

//TODO: not working ...
BOOL handleDbgKdSwitchProcessor(kd_packet_t *tmpKDPkt){
	//TODO : Manage Multiple CPU !
	curContext->curProcessor = tmpKDPkt->ManipulateState64.Processor;

	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	//TODO : function with CPU number as argument !
	//Create ExceptionStateChange Pkt
	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_STATE_CHANGE;
	tmpKDRespPkt->length = 240;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->StateChange.ApiNumber = DbgKdExceptionStateChange;
	tmpKDRespPkt->StateChange.NewState = 0x00000006;
	tmpKDRespPkt->StateChange.ProcessorLevel = tmpKDPkt->ManipulateState64.ProcessorLevel;
	tmpKDRespPkt->StateChange.Processor = tmpKDPkt->ManipulateState64.Processor;
	tmpKDRespPkt->StateChange.NumberProcessors = 0x0000;
	tmpKDRespPkt->StateChange.Thread = curContext->v_CurrentThread;
	tmpKDRespPkt->StateChange.ProgramCounter = curContext->p_curRIP;

	//Works without this... TODO:
	/*tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionCode = 0x80000003;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionAddress = 0x0000000045158890;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.NumberParameters = 0x00000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.u1 = 0xffff4e51;
	tmpKDRespPkt->StateChange.Exception.FirstChance = 0x00000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[0] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[1] = 0x000000004579b500;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[2] = 0x0000000046abfd98;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[3] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[4] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[5] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[6] = 0x000000004579aca1;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[7] = 0x0000000046abfb70;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[8] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[9] = 0x0000000000000712;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[10] = 0x0000000000000320;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[11] = 0x0000000046abfaf0;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[12] = 0x0000000000000000;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[13] = 0x0000000000000001;
	tmpKDRespPkt->StateChange.Exception.ExceptionRecord.ExceptionInformation[14] = 0x000000004503d8ee;*/

	tmpKDRespPkt->StateChange.ControlReport.Dr6 = 0x00000000ffff0ff0;
	tmpKDRespPkt->StateChange.ControlReport.Dr7 = 0x0000000000000400;
	tmpKDRespPkt->StateChange.ControlReport.EFlags = 0x00000286;
	tmpKDRespPkt->StateChange.ControlReport.InstructionCount = 0x0010;
	for (int i = 0; i < tmpKDRespPkt->StateChange.ControlReport.InstructionCount; i++){
		tmpKDRespPkt->StateChange.ControlReport.InstructionStream[i] = readPhysical8(curContext->p_curRIP + i, curContext);
	}
	tmpKDRespPkt->StateChange.ControlReport.ReportFlags = 0x0003;
	tmpKDRespPkt->StateChange.ControlReport.SegCs = 0x0010;
	tmpKDRespPkt->StateChange.ControlReport.SegDs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegEs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegFs = 0x0053;

	sendKDPkt(tmpKDRespPkt);

	return true;
}

bool handleDbgKdSetContextApi(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 56;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ApiNumber = DbgKdSetContextApi;
	tmpKDRespPkt->ManipulateState64.ProcessorLevel = tmpKDPkt->ManipulateState64.ProcessorLevel;

	sendKDPkt(tmpKDRespPkt);
	return true;
}

bool handleDbgKdWriteControlSpaceApi(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_MANIP;
	tmpKDRespPkt->length = 280;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ApiNumber = DbgKdWriteControlSpaceApi;
	tmpKDRespPkt->ManipulateState64.ProcessorLevel = tmpKDPkt->ManipulateState64.ProcessorLevel;

	tmpKDRespPkt->ManipulateState64.WriteMemory.TargetBaseAddress = tmpKDPkt->ManipulateState64.WriteMemory.TargetBaseAddress;
	tmpKDRespPkt->ManipulateState64.WriteMemory.TransferCount = tmpKDPkt->ManipulateState64.WriteMemory.TransferCount;
	tmpKDRespPkt->ManipulateState64.WriteMemory.ActualBytesWritten = tmpKDPkt->ManipulateState64.WriteMemory.TransferCount;

	switch (tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress){
	case 0: //@KPCR
		break;
	case 1: //@KPRCB
		break;
	case 2: //@SpecialReagister
		//memcpy(curContext->SpecialRegister, tmpKDPkt->ManipulateState64.ReadMemory.Data, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount);
		break;
	case 3: //@KTHREAD
		break;
	default:
		printf("TODO !!!!\n");
		ParseKDPkt(tmpKDPkt);
		system("pause");
	}
	sendKDPkt(tmpKDRespPkt);
	return true;
}

bool handleDbgKdContinueApi2(kd_packet_t *tmpKDPkt){
	char tmpBuffer[65 * 1024];
	memset(tmpBuffer, 0, 65 * 1024);
	kd_packet_t *tmpKDRespPkt = (kd_packet_t*)tmpBuffer;

	tmpKDRespPkt->leader = KD_DATA_PACKET;
	tmpKDRespPkt->type = KD_PACKET_TYPE_STATE_CHANGE;
	tmpKDRespPkt->length = 251;
	tmpKDRespPkt->id = tmpKDPkt->id ^ 0x1;
	tmpKDRespPkt->ApiNumber = DbgKdLoadSymbolsStateChange;

	WDBG_resume(curContext);

	sendKDPkt(tmpKDRespPkt);
	return true;
}

//Aka Windbg->VM
DWORD WINAPI vmserver(LPVOID lpParam) {
	char tmpBuffer[65 * 1024];
	kd_packet_t *tmpKDPkt = (kd_packet_t*)tmpBuffer;

	printf("Starting Fake-VM KD Server\n");
	while (serverRunning == 1){
		int pktType = ReadKDPipe(DBGPipe, tmpKDPkt);

		if (pktType == FASTBREAK_PKT){ //TODO: return fast-break !
			handleBreakPkt();
		}else{
			ParseKDPkt(tmpKDPkt);
			switch (tmpKDPkt->type)
			{
			case KD_PACKET_TYPE_ACK:
				//TODO: Manage missing packet
				break;
			case KD_PACKET_TYPE_RESET:
				handleResetPkt();
				break;
			case KD_PACKET_TYPE_MANIP:
			{
				switch (tmpKDPkt->ApiNumber)
				{
				case DbgKdGetVersionApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdGetVersionApiPkt(tmpKDPkt);
					break;
				case DbgKdReadVirtualMemoryApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdReadVirtualMemoryApiPkt(tmpKDPkt);
					break;
				case DbgKdReadControlSpaceApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdReadControlSpaceApi(tmpKDPkt);
					break;
				case DbgKdRestoreBreakPointApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdRestoreBreakPointApi(tmpKDPkt);
					break;
				case DbgKdClearAllInternalBreakpointsApi:
					ackKDPkt(tmpKDPkt);
					//TODO: handleDbgKdClearAllInternalBreakpointsApi
					break;
				case DbgKdGetRegister:
					ackKDPkt(tmpKDPkt);
					handleDbgKdGetRegister(tmpKDPkt);
					break;
				case DbgKdSwitchProcessor:
					ackKDPkt(tmpKDPkt);
					handleDbgKdSwitchProcessor(tmpKDPkt);
					break;
				case DbgKdSetContextApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdSetContextApi(tmpKDPkt);
					break;
				case DbgKdWriteControlSpaceApi:
					ackKDPkt(tmpKDPkt);
					handleDbgKdWriteControlSpaceApi(tmpKDPkt);
					break;
				case DbgKdContinueApi2:
					ackKDPkt(tmpKDPkt);
					handleDbgKdContinueApi2(tmpKDPkt);
					break;
				default:
					printf("[DEBUG] Unknown ApiNumber %08x\n", tmpKDPkt->ApiNumber);
					ParseKDPkt(tmpKDPkt);
					system("pause");
					break;
				}
				break;
			}
			default:
				printf("[DEBUG] Unknown Type %d\n", tmpKDPkt->type);
				ParseKDPkt(tmpKDPkt);
				system("pause");
				break;
			}
		}

	}
	return 0;
}

//TODO: move it in utils.cpp
BOOL OpenDMPFile(analysisContext_t *context){
	HANDLE	hfile = CreateFileA(context->dmpFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);

	if (hfile == INVALID_HANDLE_VALUE){
		fprintf(stderr, "CreateFile() error 0x%08x\n", GetLastError());
		getchar();
		return false;
	}

	HANDLE map_handle = CreateFileMapping(hfile, NULL, PAGE_READWRITE | SEC_RESERVE, 0, 0, 0);
	if (map_handle == NULL)
	{
		fprintf(stderr, "CreateFileMapping() error 0x%08x\n", GetLastError());
		getchar();
		CloseHandle(hfile);
		return false;
	}

	context->physicalMemory = (const unsigned char*)MapViewOfFile(map_handle, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (context->physicalMemory == NULL)
	{
		fprintf(stderr, "MapViewOfFile() error 0x%08x\n", GetLastError());
		getchar();
		CloseHandle(map_handle);
		CloseHandle(hfile);
		return false;
	}

	GetFileSizeEx(hfile, (LARGE_INTEGER*)&context->physicalMemorySize);
	return true;
}

bool initKDServer(analysisContext_t *context){
	curContext = context; //TODO: remove this !
	context->curProcessor = 0;
	if (curContext->curMode == DEBUGGED_IMAGE_TYPE //TODO: clean it !
	|| curContext->curMode == STOCK_IMAGE_TYPE){
		if (OpenDMPFile(context) == false){
			printf("Unable to open file !\n");
			return false;
		}
	}
	if (curContext->curMode == STOCK_VBOX_TYPE){
		if (OpenNamedPipe(&curContext->toVMPipe, context->dmpFileName) == false){
			printf("Unable to open FDP named pipe\n");
			system("pause");
			return false;
		}
	}
	if (initialeAnalysis(context) == false){
		printf("Unable to initiale analysis !\n");
		return false;
	}
	
	printf("KD Server Initialisation OK !\n");
	//system("pause");
	return true;
}

bool startKDServer(){
	CreateNamedPipe(&DBGPipe, "\\\\.\\pipe\\client");

	Sleep(1000);
	serverRunning = 1;

	CreateThread(NULL, 0, vmserver, NULL, 0, NULL);

	//TODO: watchdog...
	while (1){
		Sleep(1000);
	}
}

void stopKDServer(){
	serverRunning = 0;
}