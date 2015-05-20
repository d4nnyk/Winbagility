#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "mmu.h"
#include "kd.h"
#include "utils.h"
#include "dissectors.h"


HANDLE DBGPipe; //Windbg->Proxy
HANDLE VMPipe; //Proxy->VM
UINT8 serverRunning;


//TODO: structure !
const unsigned char* raw_memory_dump;
uint64_t raw_memory_size;
uint64_t p_DirectoryTableBase;
uint64_t p_KPCR;
uint64_t v_KPCR;
uint64_t p_KPRCB;
uint64_t v_KPRCB;
uint64_t v_CurrentThread;
uint64_t p_DbgBreakPointWithStatus;
uint64_t v_DbgBreakPointWithStatus;
uint64_t v_curRIP;
uint64_t p_curRIP;
uint64_t p_KDBG;
uint64_t v_KDBG;
uint64_t v_KernBase;
uint64_t v_PsLoadedModuleList;
uint64_t p_DebuggerDataList;
uint64_t v_DebuggerDataList;

BOOL sendKDPkt(kd_packet_t* toSendKDPkt){
	toSendKDPkt->checksum = ChecksumKD(toSendKDPkt);
	//ParseKDPkt(toSendKDPkt);
	DWORD numBytesWritten = WriteKDPipe(DBGPipe, toSendKDPkt);
	printf("[FAKEVM->Windbg] Write to Windbg : %d\n", numBytesWritten);
	return true;
}

//
BOOL handleBreakPkt(){
	char endOfData = 0x62; //Define fast-break !
	printf("[BREAK]\n");

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
	//tmpKDRespPkt->StateChange.Thread = 0xFFFFF8034535DA00; //Original !
	tmpKDRespPkt->StateChange.Thread = v_CurrentThread;
	//tmpKDRespPkt->StateChange.ProgramCounter = 0xFFFFF80345158890; //Original !
	tmpKDRespPkt->StateChange.ProgramCounter = v_DbgBreakPointWithStatus; //Original !

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
		tmpKDRespPkt->StateChange.ControlReport.InstructionStream[i] = *(raw_memory_dump + p_curRIP + i);
	}
	tmpKDRespPkt->StateChange.ControlReport.ReportFlags = 0x0003;
	tmpKDRespPkt->StateChange.ControlReport.SegCs = 0x0010;
	tmpKDRespPkt->StateChange.ControlReport.SegDs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegEs = 0x002b;
	tmpKDRespPkt->StateChange.ControlReport.SegFs = 0x0053;


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
	//tmpKDRespPkt->ManipulateState64.GetVersion.KernelImageBase = 0xFFFFF80345001000;
	tmpKDRespPkt->ManipulateState64.GetVersion.KernelImageBase = v_KernBase;
	//tmpKDRespPkt->ManipulateState64.GetVersion.PsLoadedModuleList = 0xFFFFF803452DA850;
	tmpKDRespPkt->ManipulateState64.GetVersion.PsLoadedModuleList = v_PsLoadedModuleList;
	//tmpKDRespPkt->ManipulateState64.GetVersion.DebuggerDataList = 0xFFFFF803452F17B8;
	tmpKDRespPkt->ManipulateState64.GetVersion.DebuggerDataList = v_DebuggerDataList;
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
	readMMU((char*)tmpKDRespPkt->ManipulateState64.ReadMemory.Data, tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress, p_DirectoryTableBase, raw_memory_dump, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount);

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
	//TODO:  2 @SpecialReagister
	switch (tmpKDPkt->ManipulateState64.ReadMemory.TargetBaseAddress){
	case 0: //@KPCR
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &v_KPCR, 8);
		break;
	case 1: //@KPRCB
		//UINT64 KPRCB = 0xfffff80345304180; //Original
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &v_KPRCB, 8);
		break;
	case 2:
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, raw_memory_dump + p_KPRCB + 0x40 + 0x00, tmpKDPkt->ManipulateState64.ReadMemory.TransferCount);
		break;
	case 3: //@KTHREAD
		memcpy(tmpKDRespPkt->ManipulateState64.ReadMemory.Data, &v_CurrentThread, 8);
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
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[5] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[6] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[7] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[8] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[9] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[10] = 0x0000000000000000;
	tmpKDRespPkt->ManipulateState64.GetRegisters.u[11] = 0x00001F800010001F;

	tmpKDRespPkt->ManipulateState64.GetRegisters.SegCs = 0x10;
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegDs = 0x2b;
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegEs = 0x2b;
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegFs = 0x53;
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegGs = 0x2b;
	tmpKDRespPkt->ManipulateState64.GetRegisters.SegSs = 0x18;
	tmpKDRespPkt->ManipulateState64.GetRegisters.Rip = v_curRIP;
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

//Aka Windbg->VM
DWORD WINAPI vmserver(LPVOID lpParam) {
	char tmpBuffer[65 * 1024];
	kd_packet_t *tmpKDPkt = (kd_packet_t*)tmpBuffer;

	printf("Starting Fake-VM KD Server\n");
	BOOL result;
	while (serverRunning == 1){
		int pktType = ReadKDPipe(DBGPipe, tmpKDPkt);

		if (pktType == FASTBREAK_PKT){ //TODO: return fast-break !
			handleBreakPkt();
		}else{
			//ParseKDPkt(tmpKDPkt);
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

BOOL OpenDMPFile(){
	HANDLE	hfile = CreateFile(L"C:\\8_1_x64.dmp", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "CreateFile() error 0x%08x\n", GetLastError());
		getchar();
		return 1;
	}

	HANDLE map_handle = CreateFileMapping(hfile, NULL, PAGE_READWRITE | SEC_RESERVE, 0, 0, 0);
	if (map_handle == NULL)
	{
		fprintf(stderr, "CreateFileMapping() error 0x%08x\n", GetLastError());
		getchar();
		CloseHandle(hfile);
		return 1;
	}

	raw_memory_dump = (const unsigned char*)MapViewOfFile(map_handle, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	if (raw_memory_dump == NULL)
	{
		fprintf(stderr, "MapViewOfFile() error 0x%08x\n", GetLastError());
		getchar();
		CloseHandle(map_handle);
		CloseHandle(hfile);
		return 1;
	}

	GetFileSizeEx(hfile, (LARGE_INTEGER*)&raw_memory_size);
}

BOOL initKDServer(){
	OpenDMPFile();

	//TODO: initial analysis function !
	p_DirectoryTableBase = findDTB(raw_memory_dump, raw_memory_size);
	printf("p_DirectoryTableBase : 0x%p\n", p_DirectoryTableBase);
	p_KPCR = findKPCR(0, p_DirectoryTableBase, raw_memory_dump, raw_memory_size);
	printf("p_KPCR : %p\n", p_KPCR);
	v_KPCR = BYTESWAP64(read64(p_KPCR + 0x18, raw_memory_dump));
	printf("v_KPCR : %p\n", v_KPCR);
	p_KPRCB = p_KPCR + 0x180;
	printf("p_KPRCB : %p\n", p_KPRCB);
	v_KPRCB = BYTESWAP64(read64(p_KPCR + 0x20, raw_memory_dump));
	printf("v_KPRCB : %p\n", v_KPRCB);
	v_CurrentThread = BYTESWAP64(read64(p_KPRCB + 8, raw_memory_dump));
	printf("v_CurrentThread : 0x%p !\n", v_CurrentThread);
	p_KDBG = findKDBG(raw_memory_dump, raw_memory_size);
	v_KDBG = physical_virtual(p_KDBG, p_DirectoryTableBase, raw_memory_dump, raw_memory_size);

	printf("v_KDBG : %p\n", v_KDBG);
	v_KernBase = BYTESWAP64(read64(p_KDBG + 0x18, raw_memory_dump));
	printf("v_KernBase : %p\n", v_KernBase);
	v_PsLoadedModuleList = BYTESWAP64(read64(p_KDBG + 0x48, raw_memory_dump));
	printf("v_PsLoadedModuleList : %p\n", v_PsLoadedModuleList);
	v_DbgBreakPointWithStatus = BYTESWAP64(read64(p_KDBG + 0x20, raw_memory_dump));
	printf("v_DbgBreakPointWithStatus : %p\n", v_DbgBreakPointWithStatus);
	v_curRIP = v_DbgBreakPointWithStatus; //Raw mode...
	printf("v_curRIP : %p\n", v_curRIP);
	p_curRIP = virtual_physical(v_curRIP, p_DirectoryTableBase, raw_memory_dump, raw_memory_size);
	printf("p_curRIP : %p\n", p_curRIP);
	p_DebuggerDataList = findDebuggerDataList(v_KDBG, raw_memory_dump, raw_memory_size);
	printf("p_DebuggerDataList : %p\n", p_DebuggerDataList);
	v_DebuggerDataList = physical_virtual(p_DebuggerDataList, p_DirectoryTableBase, raw_memory_dump, raw_memory_size);
	printf("v_DebuggerDataList : %p\n", v_DebuggerDataList);
	
	system("pause");
	return true;
}

BOOL startKDServer(){
	CreateDBGNamedPipe(&DBGPipe);

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