#pragma once

#include <ntddk.h>


#define SIRIFEF_LOADLIBRARYEXA_ADDRESS 1268416216


typedef PVOID(*fnLoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	ULONG  dwFlags
	);


typedef struct _SIRIFEF_INJECTION_DATA
{
	BOOLEAN Executing;
	PEPROCESS Process;
	PETHREAD Ethread;
	KEVENT Event;
	WORK_QUEUE_ITEM WorkItem;
	ULONG ProcessId;

}SIRIFEF_INJECTION_DATA, *PSIRIFEF_INJECTION_DATA;

typedef struct GET_ADDRESS
{
	PVOID Kernel32dll;
	fnLoadLibraryExA pvLoadLibraryExA;

}GET_ADDRESS, *PGET_ADDRESS;

extern PGET_ADDRESS GET_SIRIFEF_ADDRESS;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
	);

typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
	);

BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
	);


VOID Unload(IN PDRIVER_OBJECT pDriverobject);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverobject, IN PUNICODE_STRING pRegister);
VOID NTAPI APCKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID *SysArg1, PVOID *SysArg2, PVOID *Context);
NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS Peprocess, PETHREAD Pethread, BOOLEAN Alert);
VOID LoadImageNotifyRoutine(IN PUNICODE_STRING ImageName, IN HANDLE ProcessId, IN PIMAGE_INFO pImageInfo);
VOID NTAPI APCInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *SystemArgument1, PVOID *SystemArgument2, PVOID *Context);
VOID SirifefWorkerRoutine(PVOID Context);
UINT32 HashString(PCHAR pcString);
PVOID GetProcedureAddressByHash(PVOID ModuleBase, ULONG Hash, ULONG Data);
VOID NTAPI LoadDynamicFunctions(PGET_ADDRESS Hash);
PVOID ResolveDynamicImport(PVOID ModuleBase, ULONG Hash);

extern GET_ADDRESS Hash;