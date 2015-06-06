#ifndef __KD_H__
#define __KD_H__

#include <windows.h>
#include <stdint.h>


#define KD_DATA_PACKET						0x30303030
#define KD_CONTROL_PACKET					0x69696969
//
// Wait State Change Types
//
#define DbgKdMinimumStateChange             0x00003030
#define DbgKdExceptionStateChange           0x00003030
#define DbgKdLoadSymbolsStateChange         0x00003031
#define DbgKdCommandStringStateChange       0x00003032
#define DbgKdMaximumStateChange             0x00003033

#define DbgKdMinimumManipulate              0x00003130
#define DbgKdReadVirtualMemoryApi           0x00003130
#define DbgKdWriteVirtualMemoryApi          0x00003131
#define DbgKdGetContextApi                  0x00003132
#define DbgKdSetContextApi                  0x00003133
#define DbgKdWriteBreakPointApi             0x00003134
#define DbgKdRestoreBreakPointApi           0x00003135
#define DbgKdContinueApi                    0x00003136
#define DbgKdReadControlSpaceApi            0x00003137
#define DbgKdWriteControlSpaceApi           0x00003138
#define DbgKdReadIoSpaceApi                 0x00003139
#define DbgKdWriteIoSpaceApi                0x0000313A
#define DbgKdRebootApi                      0x0000313B
#define DbgKdContinueApi2                   0x0000313C
#define DbgKdReadPhysicalMemoryApi          0x0000313D
#define DbgKdWritePhysicalMemoryApi         0x0000313E
#define DbgKdQuerySpecialCallsApi           0x0000313F
#define DbgKdSetSpecialCallApi              0x00003140
#define DbgKdClearSpecialCallsApi           0x00003141
#define DbgKdSetInternalBreakPointApi       0x00003142
#define DbgKdGetInternalBreakPointApi       0x00003143
#define DbgKdReadIoSpaceExtendedApi         0x00003144
#define DbgKdWriteIoSpaceExtendedApi        0x00003145
#define DbgKdGetVersionApi                  0x00003146
#define DbgKdWriteBreakPointExApi           0x00003147
#define DbgKdRestoreBreakPointExApi         0x00003148
#define DbgKdCauseBugCheckApi               0x00003149
#define DbgKdSwitchProcessor                0x00003150
#define DbgKdPageInApi                      0x00003151
#define DbgKdReadMachineSpecificRegister    0x00003152
#define DbgKdWriteMachineSpecificRegister   0x00003153
#define OldVlm1                             0x00003154
#define OldVlm2                             0x00003155
#define DbgKdSearchMemoryApi                0x00003156
#define DbgKdGetBusDataApi                  0x00003157
#define DbgKdSetBusDataApi                  0x00003158
#define DbgKdCheckLowMemoryApi              0x00003159
#define DbgKdClearAllInternalBreakpointsApi 0x0000315A
#define DbgKdFillMemoryApi                  0x0000315B
#define DbgKdQueryMemoryApi                 0x0000315C
#define DbgKdSwitchPartition                0x0000315D
#define DbgKdMaximumManipulate              0x0000315E
//New in v8
#define DbgKdGetRegister                    0x0000315F

#define DbgKdPrintStringApi					0x00003230
#define DbgKdGetStringApi					0x00003231



#define KD_PACKET_TYPE_MANIP	2
#define KD_PACKET_TYPE_ACK		4
#define KD_PACKET_TYPE_RESEND	5
#define KD_PACKET_TYPE_RESET	6
#define KD_PACKET_TYPE_STATE_CHANGE 7
#define KD_PACKET_TYPE_IO		11

#pragma pack()
typedef struct _AMD64_DBGKD_CONTROL_SET
{
	ULONG TraceFlag;
	ULONG64 Dr7;
	ULONG64 CurrentSymbolStart;
	ULONG64 CurrentSymbolEnd;
} AMD64_DBGKD_CONTROL_SET, *PAMD64_DBGKD_CONTROL_SET;

typedef struct _DBGKD_CONTINUE2
{
	NTSTATUS ContinueStatus;
	AMD64_DBGKD_CONTROL_SET ControlSet;
} DBGKD_CONTINUE2, *PDBGKD_CONTINUE2;

//
// Format of data for fnsave/frstor instructions.
//
// This structure is used to store the legacy floating point state.
//
typedef struct _AMD64_LEGACY_SAVE_AREA {
	USHORT ControlWord;
	USHORT Reserved0;
	USHORT StatusWord;
	USHORT Reserved1;
	USHORT TagWord;
	USHORT Reserved2;
	ULONG ErrorOffset;
	USHORT ErrorSelector;
	USHORT ErrorOpcode;
	ULONG DataOffset;
	USHORT DataSelector;
	USHORT Reserved3;
	UCHAR FloatRegisters[8 * 10];
} AMD64_LEGACY_SAVE_AREA, *PAMD64_LEGACY_SAVE_AREA;

typedef struct _AMD64_M128 {
	ULONGLONG Low;
	LONGLONG High;
} AMD64_M128, *PAMD64_M128;

//TODO: rename
//http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/public/internal/sdktools/inc/ntdbg.h
typedef struct _DBGKD_GET_REGISTER64{
	ULONG64 u[12];


	//
	// Control flags.
	//

	//ULONG ContextFlags;
	//ULONG MxCsr;

	//
	// Segment Registers and processor flags.
	//

	USHORT SegCs;
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
	USHORT SegGs;
	USHORT SegSs;
	ULONG EFlags;

	//
	// Debug registers
	//

	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr6;
	ULONG64 Dr7;

	//
	// Integer registers.
	//

	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
	ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;

	//
	// Program counter.
	//
	ULONG64 Rip;

	ULONG64 DATA[122];
}DBGKD_GET_REGISTER64, *PBGKD_GET_REGISTER64;

typedef struct _DBGKD_RESTORE_BREAKPOINT
{
	ULONG BreakPointHandle;
	UINT8 Unknown[36];
} DBGKD_RESTORE_BREAKPOINT, *PDBGKD_RESTORE_BREAKPOINT;

//https://github.com/Piker-Alpha/macosxbootloader/blob/master/src/boot/BootDebuggerPrivate.h
typedef struct _DBGKD_GET_VERSION_API64
{
	UINT16  MajorVersion;
	UINT16	MinorVersion;
	UINT16	ProtocolVersion;
	UINT16  Flags;
	UINT16	MachineType;
	UINT8	MaxPacketType;
	UINT8	MaxStateChange;
	UINT8	MaxManipulate;
	UINT8	Simulation;
	UINT16	Unknown1; //0x0000
	ULONG64 KernelImageBase;
	ULONG64 PsLoadedModuleList;
	ULONG64 DebuggerDataList;
	UINT64 Unknown2; //0xABABABABFDFDFDFD
	UINT64 Unknown3; //0xABABABABABABABAB
} DBGKD_GET_VERSION_API64, *PDBGKD_GET_VERSION_API64;

typedef struct _DBGKD_WRITE_MEMORY64
{
	UINT64 TargetBaseAddress;
	ULONG TransferCount;
	ULONG ActualBytesWritten;
} DBGKD_WRITE_MEMORY64, *PDBGKD_WRITE_MEMORY64;

typedef struct _DBGKD_READ_MEMORY64
{
	UINT64 TargetBaseAddress;
	UINT32 TransferCount;
	UINT32 ActualBytesRead;
	UINT64 Unknown1; //Don't know... But Useless Windbg is OK, if setted 0x00
	UINT64 Unknown2; //Don't know... But Useless Windbg is OK, if setted 0x00
	UINT64 Unknown3; //Don't know... But Useless Windbg is OK, if setted 0x00
	UINT8 Data[0];
} DBGKD_READ_MEMORY64, *PDBGKD_READ_MEMORY64;


typedef struct _DBGKD_MANIPULATE_STATE64
{
	UINT32 ApiNumber;
	UINT16 ProcessorLevel;
	UINT16 Processor;
	NTSTATUS ReturnStatus;
	//UINT32 Padding;
	union
	{
		DBGKD_READ_MEMORY64 ReadMemory;
		DBGKD_WRITE_MEMORY64 WriteMemory;
		/*DBGKD_GET_CONTEXT GetContext;*/
		//DBGKD_SET_CONTEXT SetContext;
		//DBGKD_WRITE_BREAKPOINT64 WriteBreakPoint;
		DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
		/*DBGKD_CONTINUE Continue;*/
		DBGKD_CONTINUE2 Continue2;
		/*DBGKD_READ_WRITE_IO64 ReadWriteIo;
		DBGKD_READ_WRITE_IO_EXTENDED64 ReadWriteIoExtended;
		DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
		DBGKD_SET_SPECIAL_CALL64 SetSpecialCall;
		DBGKD_SET_INTERNAL_BREAKPOINT64 SetInternalBreakpoint;
		DBGKD_GET_INTERNAL_BREAKPOINT64 GetInternalBreakpoint;
		DBGKD_GET_VERSION64 GetVersion64;
		DBGKD_BREAKPOINTEX BreakPointEx;
		DBGKD_READ_WRITE_MSR ReadWriteMsr;
		DBGKD_SEARCH_MEMORY SearchMemory;
		DBGKD_GET_SET_BUS_DATA GetSetBusData;
		DBGKD_FILL_MEMORY FillMemory;*/
		//DBGKD_QUERY_MEMORY QueryMemory;
		/*DBGKD_SWITCH_PARTITION SwitchPartition;*/
		DBGKD_GET_REGISTER64 GetRegisters;
		DBGKD_GET_VERSION_API64 GetVersion;
		char data[1024]; //XXX: for testing
	};
} DBGKD_MANIPULATE_STATE64, *PDBGKD_MANIPULATE_STATE64;

#define EXCEPTION_MAXIMUM_PARAMETERS 15
typedef struct _EXCEPTION_RECORD644
{
	UINT32 ExceptionCode;
	UINT32 ExceptionFlags;
	UINT64 ExceptionRecord;
	UINT64 ExceptionAddress;
	UINT32 NumberParameters;
	UINT32 u1;
	UINT64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD644, *PEXCEPTION_RECORD644;

typedef struct _DBGKM_EXCEPTION64
{
	EXCEPTION_RECORD644 ExceptionRecord;
	UINT32 FirstChance;
} DBGKM_EXCEPTION64, *PDBGKM_EXCEPTION64;

#define DBGKD_MAXSTREAM 16 
typedef struct _AMD64_DBGKD_CONTROL_REPORT
{
	ULONG64 Dr6;
	ULONG64 Dr7;
	ULONG EFlags;
	USHORT InstructionCount;
	USHORT ReportFlags;
	UCHAR InstructionStream[DBGKD_MAXSTREAM];
	USHORT SegCs;
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
} AMD64_DBGKD_CONTROL_REPORT, *PAMD64_DBGKD_CONTROL_REPORT;

typedef struct _DBGKD_WAIT_STATE_CHANGE64
{
	UINT32 ApiNumber;
	ULONG NewState;
	USHORT ProcessorLevel;
	USHORT Processor;
	ULONG NumberProcessors;
	ULONG64 Thread;
	ULONG64 ProgramCounter;
	union
	{
		DBGKM_EXCEPTION64 Exception;
		//DBGKD_LOAD_SYMBOLS64 LoadSymbols;
	};
	AMD64_DBGKD_CONTROL_REPORT ControlReport;
} DBGKD_WAIT_STATE_CHANGE64, *PDBGKD_WAIT_STATE_CHANGE64;

typedef struct kd_packet_t{
	UINT32 leader;
	UINT16 type;
	UINT16 length;
	UINT32 id;
	UINT32 checksum;
	union{
		UINT32 ApiNumber;
		DBGKD_MANIPULATE_STATE64 ManipulateState64;
		DBGKD_WAIT_STATE_CHANGE64 StateChange;

		UINT8 data[0];
	};
}kd_packet_t;
#pragma pack(pop)

enum{
	FASTBREAK_PKT,
	KD_PKT,
	ERR_PKT
};

//functions
uint32_t ChecksumKD(kd_packet_t *pkt);
DWORD WriteKDPipe(HANDLE hPipe, kd_packet_t *pkt);
int ReadKDPipe(HANDLE hPipe, kd_packet_t *pktBuffer);
bool ParseKDPkt(kd_packet_t* pkt);

#endif //__KD_H__