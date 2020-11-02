#include "Main.h"

LARGE_INTEGER  p ;/*注册表回调的句柄*/
ULONG32 ProtectPid = 0;/*要保护的进程Pid*/
PUNICODE_STRING RegeditPath = {0};/*自身的注册表位置*/
/*Ob进程句柄*/PVOID ob_process = NULL;
/*Ob线程句柄*/PVOID ob_thread = NULL;
//VOID * Handle = NULL;

PFLT_FILTER g_pFilterHandle = NULL;/*微小过滤器*/
PVOID JmpBase = NULL;

PVOID OldAddress = NULL;

/*卸载小型过滤器*/
NTSTATUS NPUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	FltUnregisterFilter(g_pFilterHandle);
	return STATUS_SUCCESS;
}



/*关闭进程*/
NTSTATUS KeTerminateProcess(ULONG Pid)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES attribtus = { 0 };
	HANDLE Handle = NULL;
	InitializeObjectAttributes(&attribtus, 0, 0, 0, 0);
	CLIENT_ID client = { 0 };
	client.UniqueProcess = (HANDLE)Pid;
	client.UniqueThread = NULL;
	status = ZwOpenProcess(&Handle, PROCESS_ALL_ACCESS, &attribtus, &client);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("OpenProcessFalied\n"));
		return status;
	}
	status = ZwTerminateProcess(Handle, status);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("TerminateProcessFalied\n"));
		return status;
	}
	ZwClose(Handle);
	return status;
}

/*注册表回调*/
NTSTATUS RegistryCallback(IN PVOID CallbackContext, IN PVOID Argument1, IN PVOID Argument2)
{
	UNICODE_STRING Registry = { 0 };
	NTSTATUS	CallbackStatus = STATUS_SUCCESS;

	Registry.MaximumLength = 0x1000 * sizeof(WCHAR);
	Registry.Buffer = ExAllocatePoolWithTag(NonPagedPool, Registry.MaximumLength, REGISTRY_POOL_TAG);/*申请内存*/
	if (Registry.Buffer==NULL)
	{
		return CallbackStatus;
	}
	RtlZeroMemory(Registry.Buffer, Registry.MaximumLength);

	REG_NOTIFY_CLASS t_type = (REG_NOTIFY_CLASS)Argument1;/*拿到注册表的类型*/
	switch (t_type)
	{
	case RegNtPreDeleteKey:/*删除注册项前操作*/

	default:
		break;
	}
	if (Registry.Buffer != NULL)
	{
		ExFreePoolWithTag(Registry.Buffer, REGISTRY_POOL_TAG);
	}
	return CallbackStatus;
}
/*驱动退出*/
void NTAPI Unload(IN PDRIVER_OBJECT driver)
{
	KIRQL	irp = WPOFFx64();
	RtlCopyMemory(OldAddress, JmpBase, 13);
	WPONx64(irp);
	ExFreePool(JmpBase);

	IoUnregisterShutdownNotification(driver->DeviceObject);/*首先先删除关机回调*/

	IoDeleteDevice(driver->DeviceObject);
	UNICODE_STRING Link_File_Name = { 0 };
	RtlInitUnicodeString(&Link_File_Name, LINK_PATH);
	IoDeleteSymbolicLink(&Link_File_Name);
	/**/
	CmUnRegisterCallback(p);
	if (ob_process)
	{
		ObUnRegisterCallbacks(ob_process);
	}
	if (ob_thread)
	{
		ObUnRegisterCallbacks(ob_thread);
	}

	KdPrint(("This is a Driver Unload Success!\n"));
}

NTSTATUS CreateDervice(PDRIVER_OBJECT driverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING DriverName = { 0 };

	RtlInitUnicodeString(&DriverName, DEVICE_NAME);

	PDEVICE_OBJECT Device = NULL;

	status = IoCreateDevice(driverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, TRUE, &Device);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Device Create Failed!\n"));
		return status;
	}
	
	/*创建关机回调*/
	IoRegisterShutdownNotification(Device);

	Device->Flags |= DO_BUFFERED_IO;
	
	UNICODE_STRING Link = { 0 };
	RtlInitUnicodeString(&Link, LINK_PATH);

	status = IoCreateSymbolicLink(&Link, &DriverName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(Device);
		return status;
	}

	return status;
}

/*Ob进程回调*/
OB_PREOP_CALLBACK_STATUS  PsProtectProcessEx(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if(OperationInformation->ObjectType != *PsProcessType)
		return OB_PREOP_SUCCESS;
	
	if (ProtectPid <= 4)
	{
		return OB_PREOP_SUCCESS;
	}
	PEPROCESS p = NULL;
	PCHAR Name = PsGetProcessImageFileName(OperationInformation->Object);
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		PsLookupProcessByProcessId((HANDLE)ProtectPid, &p);
		if (p == OperationInformation->Object)
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
			else if ((OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;

			}
			else if ((OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
			else if ((OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}

		}

	}
	if (p)
	{
		ObDereferenceObject(p);
	}
	return OB_PREOP_SUCCESS;
}

/*Ob线程回调*/
OB_PREOP_CALLBACK_STATUS  PsProtectThreadEx(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
#define THREAD_TERMINATE2 0x1
	PEPROCESS ep;
	PETHREAD et;
	HANDLE pid;
	if (OperationInformation->ObjectType != *PsThreadType)
		goto exit_sub;
	if (ProtectPid<=4)
	{
		return OB_PREOP_SUCCESS;
	}
	if (PsGetThreadProcessId(OperationInformation->Object) == (HANDLE)ProtectPid)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			//pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
			if ((OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
	}
exit_sub:
	return OB_PREOP_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT device, IRP *p) {

	PIO_STACK_LOCATION  status = IoGetCurrentIrpStackLocation(p);

	if (status->MajorFunction == IRP_MJ_SHUTDOWN)/*关机回调*/
	{
		WCHAR Path[] = L"\\SystemRoot\\system32\\drivers\\PGSeviceX64.sys";
		KeSetRegeditValue(RegeditPath, Path);/*关机之后设置自启动*/
		p->IoStatus.Information = sizeof(Path) / sizeof(WCHAR);
		IoCompleteRequest(p, IO_NO_INCREMENT);
		return p->IoStatus.Status = STATUS_SUCCESS;
	}

	p->IoStatus.Information = status->Parameters.DeviceIoControl.OutputBufferLength;
	
	IoCompleteRequest(p, IO_NO_INCREMENT);

	return p->IoStatus.Status = STATUS_SUCCESS;
}

NTSTATUS DispatchControl(PDEVICE_OBJECT device, IRP *p)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(p);

	ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
	
	ULONG Input = stack->Parameters.DeviceIoControl.InputBufferLength;

	ULONG info = 0;

	ULONG Type = stack->Parameters.DeviceIoControl.IoControlCode;
	switch (Type)
	{
	case TERMINATE_CODE:/*终止进程*/
	{
		ULONG Pid = *(PULONG)p->AssociatedIrp.SystemBuffer;
	
		if (NT_SUCCESS(KeTerminateProcess(Pid))) 
			*(PULONG)p->AssociatedIrp.SystemBuffer = TRUE;
		else 
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;
	
		info = sizeof(ULONG);
		break;
	}
	case SUPEND_CODE:/*暂停进程*/
	{
		ULONG Pid = *(PULONG)p->AssociatedIrp.SystemBuffer;

		PEPROCESS process=NULL;
		NTSTATUS status=PsLookupProcessByProcessId((HANDLE)Pid,&process);
		if (!NT_SUCCESS(status))
		{
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;
			break;
		}
		ObDereferenceObject(process);
		if(!NT_SUCCESS(PsSuspendProcess(process)))
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;
		else
			*(PULONG)p->AssociatedIrp.SystemBuffer = TRUE;
		
		info = sizeof(ULONG);
		break;
	}
	case RESUME_CODE:/*恢复暂停进程*/
	{
		ULONG Pid = *(PULONG)p->AssociatedIrp.SystemBuffer;

		PEPROCESS process = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Pid, &process);
		if (!NT_SUCCESS(status))
		{
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;
			break;
		}
		ObDereferenceObject(process);
		if (!NT_SUCCESS(PsResumeProcess(process)))
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;
		else 
			*(PULONG)p->AssociatedIrp.SystemBuffer = TRUE;

		info = sizeof(ULONG);
		break;
	}
	case FORBID_DRIVER_CODE:/*全局禁止驱动DLL文件禁止加载*/
	{
		BOOLEAN Start= *(BOOLEAN *)p->AssociatedIrp.SystemBuffer;
		if (Start==FALSE)
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = 0;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
			break;
		}
		/*创建模块回调*/
		NTSTATUS status=PsSetLoadImageNotifyRoutine(ForibidImage);
		if (NT_SUCCESS(status))
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = TRUE;/*告诉应用层创建成功*/
			info = sizeof(BOOLEAN);
		}
		else
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
		}
		break;
	}
	case RECOVERY_DRIVER_CODE:/*恢复驱动加载*/
	{
		BOOLEAN Start = *(BOOLEAN *)p->AssociatedIrp.SystemBuffer;
		if (Start == FALSE)
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = 0;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
			break;
		}
		NTSTATUS status=PsRemoveLoadImageNotifyRoutine(ForibidImage);
		if (NT_SUCCESS(status))
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = TRUE;/*告诉应用层创建成功*/
			info = sizeof(BOOLEAN);
		}
		else
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
		}
		break;
	}
	case FORBID_PROCESS_CODE:/*禁止创建进程*/
	{
		BOOLEAN Start = *(BOOLEAN *)p->AssociatedIrp.SystemBuffer;
		if (Start == FALSE)
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = 0;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
			break;
		}
		NTSTATUS Status = PsSetCreateProcessNotifyRoutine(ForibidProcess, FALSE);
		if (NT_SUCCESS(Status))
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = TRUE;/*告诉应用层创建成功*/
			info = sizeof(BOOLEAN);
		}
		else
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
		}

		break;
	}
	case RECOVERY_PROCESS_CODE:/*恢复创建进程*/
	{
		BOOLEAN Start = *(BOOLEAN *)p->AssociatedIrp.SystemBuffer;
		if (Start == FALSE)
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = 0;/*告诉应用层创建失败*/
			info = sizeof(BOOLEAN);
			break;
		}
		NTSTATUS Status = PsSetCreateProcessNotifyRoutine(ForibidProcess, TRUE);
		if (NT_SUCCESS(Status))
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = TRUE;/*告诉应用层关闭成功*/
			info = sizeof(BOOLEAN);
		}
		else
		{
			*(BOOLEAN *)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层关闭失败*/
			info = sizeof(BOOLEAN);
		}
		break;

	}
	case DELETE_CODE:/*删除文件宽字符*/
	{
		PWCHAR path = (PWCHAR)p->AssociatedIrp.SystemBuffer;
		if (!MmIsAddressValid(path))
		{
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层文件路径无效*/
			info = 4;
			break;
		}
		UNICODE_STRING filepath = { 0 };

		RtlInitUnicodeString(&filepath, path);

		if(!NT_SUCCESS(DelDriverFile(&filepath))) *(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层文件路径无效*/

		else  *(PULONG)p->AssociatedIrp.SystemBuffer = TRUE;/*告诉应用层删除成功*/
		info = output;
		break;
	}
	case GETPROCESS_PId_CODE:/*获取进程Pid*/
	{
		PWCHAR p_name = (PWCHAR)p->AssociatedIrp.SystemBuffer;
		if (!MmIsAddressValid(p_name))
		{
			*(ULONG *)p->AssociatedIrp.SystemBuffer = 0;/*内存不够*/
			info = sizeof(ULONG);
			break;
		}
		ULONG Pid=*(ULONG  *)PsGetProcessPid(p_name);
		*(ULONG *)p->AssociatedIrp.SystemBuffer = Pid;
		info = sizeof(ULONG);
		break;
	}
	case PROCESSPROCECT_CODE:/*保护进程*/
	{
		if (*(PULONG)p->AssociatedIrp.SystemBuffer <=4)
		{
			*(PULONG)p->AssociatedIrp.SystemBuffer = FALSE;/*告诉应用层文件路径无效*/
			info = 4;
			break;
		}
		ProtectPid = *(PULONG)p->AssociatedIrp.SystemBuffer;
		info = sizeof(PULONG);
		break;
	}
	case Write_code:/*写内存*/
	{
		PWRITEPROCESS temp = (PWRITEPROCESS)p->AssociatedIrp.SystemBuffer;
		WriteProcessMemroy(temp->Pid, temp->Address, temp->Data);
		info = sizeof(PWRITEPROCESS);
		break;
	}
	case Read_code:/*读内存*/
	{
		PPROCESS_READ temp = (PPROCESS_READ)p->AssociatedIrp.SystemBuffer;
		PVOID data = ReadProcessMemroy(temp->Pid, temp->Address);
		p->AssociatedIrp.SystemBuffer = data;
		info = sizeof(PPROCESS_READ);
		break;
	}
	case Module_code:/*取模块地址*/
	{
		PMODULE tempmodule = (PMODULE)p->AssociatedIrp.SystemBuffer;

		ANSI_STRING tmepstr = { 0 };
		RtlInitAnsiString(&tmepstr, tempmodule->ModuleName);
		UNICODE_STRING ModuleName = { 0 };
		RtlAnsiStringToUnicodeString(&ModuleName, &tmepstr, TRUE);
		ULONG64 Base = GetProcessModuleHandle(tempmodule->Pid, &ModuleName);
		(ULONG64)p->AssociatedIrp.SystemBuffer = Base;
		info = sizeof(PMODULE);
		break;
	}
	case Delete_code:/*删除文件*/
	{
		/**/
		PUNICODE_STRING Path = NULL;
		PCHAR FilePath = (PCHAR)p->AssociatedIrp.SystemBuffer;
		ANSI_STRING str = { 0 };
		CHAR Arrays[255];
		RtlZeroMemory(Arrays, sizeof(Arrays));
		strcpy_s(Arrays, sizeof(Arrays), FilePath);
		RtlInitAnsiString(&str, Arrays);

		NTSTATUS status = RtlAnsiStringToUnicodeString(Path, &str, TRUE);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("Get Path Failed\n"));
			info = 0;
			break;
		}
		DelDriverFile(Path);
		info  = sizeof(PCHAR);
		break;
	}
	default:
		break;
	}
	p->Flags |= DO_BUFFERED_IO;
	p->IoStatus.Status = STATUS_SUCCESS;
	p->IoStatus.Information = info;
	IoCompleteRequest(p,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
/**/
NTSTATUS Dispath_Attach(PDEVICE_OBJECT device, IRP *p)
{
	PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(p);

	if (stack->MajorFunction!=IRP_MJ_READ  || stack->MajorFunction==IRP_MJ_POWER)/*如果不是读的操作，全部过滤*/
	{
		PoStartNextPowerIrp(p);
		IoGetCurrentIrpStackLocation(p);/*告诉设备已经请求过了*/
		return PoCallDriver(device,p);
	}
	/*过滤读的长度*/
	ULONG Len = stack->Parameters.Read.Length;
	if (Len>0x1000 * 2)
	{
		/*如果长度大于4096字节,返回错误码*/
		return STATUS_UNSUCCESSFUL;
	}
	p->IoStatus.Information = sizeof(Len);
	p->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(p,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*模块监控*/
VOID  ForibidImage(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
	if (MmIsAddressValid(FullImageName) && FullImageName!=NULL)
	{
		
		
		if (ProcessId==NULL)
		{
			/*HANDLE p = NULL;
			OBJECT_ATTRIBUTES object = { 0 };
			InitializeObjectAttributes(&object, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			PsCreateSystemThread(&p, 0, &object, NULL, NULL, MyModuleProc, (PVOID)ImageInfo);

			ZwClose(p);*/
			RemoveDriverFile(ImageInfo->ImageBase);/*禁止驱动文件加载*/
		}
		
		
	}
}

BOOLEAN  RemoveDriverFile(PVOID ImageBase)
{
	PIMAGE_DOS_HEADER  dosHeader = (PIMAGE_DOS_HEADER)ImageBase;


	PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)dosHeader + dosHeader->e_lfanew);

	PVOID AddressEntry = (PVOID)((ULONG64)dosHeader + NtHeader->OptionalHeader.AddressOfEntryPoint);

	UCHAR ShellCode[] = { 0xB8,0x22,0x00,0x00,0xC0,0xC3 };

	PMDL mdl = IoAllocateMdl(ShellCode, sizeof(ShellCode), FALSE, FALSE, NULL);
	PVOID MdlAddress = NULL;
	if (!mdl)
	{
		KdPrint(("IoAllocateMdl failed!\n"));
		return FALSE;
	}

	__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		MdlAddress =MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);/*If the return is successful, the new memory address is obtained*/
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	
	if (!MdlAddress)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	KIRQL irql = WPOFFx64();

	RtlCopyMemory(AddressEntry, MdlAddress, sizeof(ShellCode));

	WPONx64(irql);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return TRUE;
}

BOOLEAN RemoveDLLFile(PVOID ImageBase)
{
	ULONG ImageSize = 0xC * 16 + 0x8;
	PMDL mdl = MmCreateMdl(NULL, ImageBase, ImageSize);
	if (!mdl)
	{
		KdPrint(("Create Mdl Falied!\n"));
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(mdl);
	PVOID Base = MmMapLockedPages(mdl, KernelMode);
	if (!Base)
	{
		IoFreeMdl(mdl);
		KdPrint(("Locked Mdl Falied!\n"));
		return FALSE;
	}
	RtlZeroMemory(Base, ImageSize);


	MmUnlockPages(mdl);

	IoFreeMdl(mdl);
	return TRUE;

}

/*进程监控*/
VOID  ForibidProcess(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
	if (Create)
	{
		HANDLE p = NULL;
		OBJECT_ATTRIBUTES object = { 0 };
		InitializeObjectAttributes(&object,NULL,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
		KdPrint(("Process Id:[%d]\n", ProcessId));
		PsCreateSystemThread(&p,0, &object,NULL,NULL, MyTheadProc,(PVOID)ProcessId);

		ZwClose(p);
	}
	
	
}
/*终止进程回调*/
void MyTheadProc(PVOID context)
{
	PEPROCESS p=NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)context, &p)))
	{
		/*explorer*/
		ObDereferenceObject(p);/*拿到解一次引用*/
		if (strstr(PsGetProcessImageFileName(p),"Taskmgr.exe") || strstr(PsGetProcessImageFileName(p), "notepad.exe") || strstr(PsGetProcessImageFileName(p), "taskmgr.exe") || strstr(PsGetProcessImageFileName(p), "explorer.exe") || strstr(PsGetProcessImageFileName(p), "Explorer.exe"))
		{
			PsTerminateSystemThread(STATUS_SUCCESS);/*不终止进程*/
			return;
		}
		else  if(((PCHAR)p+0x23)==0)/*debug创建的*/
		{
			KeTerminateProcess((ULONG64)((HANDLE)context));
			PsTerminateSystemThread(STATUS_SUCCESS);/*不终止进程*/
			return;
		}
	}
	
	KeTerminateProcess((ULONG64)((HANDLE)context));
	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

/*获取进程模块地址*/
ULONG64 GetProcessModuleHandle(ULONG pid, PUNICODE_STRING ModuleName)
{
	PEPROCESS p;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 Base = 0;
	status = PsLookupProcessByProcessId((HANDLE)pid, &p);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("获取PidFalied\n"));
		return 0;
	}
	KAPC_STATE kepc_state = { 0 };
	KeStackAttachProcess(p, &kepc_state);

	PMYPEB peb = PsGetProcessPeb(p);
	if (peb == NULL)
	{
		KdPrint(("Get peb Falied\n"));
		goto __falied;
	}
	PPEB_LDR_DATA ladr_data = (PPEB_LDR_DATA)peb->Ldr;
	PLIST_ENTRY  NtBaseStart, NtBaseEnd;
	PLDR_DATA_TABLE_ENTRY tempdata = NULL;
	__try
	{
		NtBaseStart = NtBaseEnd = ladr_data->InMemoryOrderModuleList.Blink;
		do
		{
			tempdata = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(NtBaseStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (RtlCompareUnicodeString(ModuleName, &tempdata->BaseDllName, TRUE) == 0)
			{
				Base = (ULONG64)tempdata->DllBase;
				KdPrint(("Get Module :[%x]", Base));
				break;
			}
			NtBaseStart = NtBaseStart->Blink;
		} while (NtBaseStart != NtBaseEnd);

	}
	__except (1)
	{
		KdPrint(("蓝精灵捕捉一枚\n"));
	}
__falied:
	ObDereferenceObject(p);
	KeUnstackDetachProcess(&kepc_state);
	return Base;
}

/*DeleteFile*/
NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath)
{
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		pUsDriverPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		0,
		0);

	NTSTATUS Status = IoCreateFileEx(&FileHandle,
		SYNCHRONIZE | DELETE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PFILE_OBJECT FileObject;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		'eliF',
		(PVOID*)(&FileObject),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return Status;
	}

	const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = NULL;

	// 调用MmFlushImageSection，使其认为没有备份镜像，让NTFS释放文件锁
	CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

	if (ImageSectionFlushed)
	{
		// chicken fried rice
		Status = ZwDeleteFile(&ObjectAttributes);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}
	}
	return Status;

}

/*把驱动设置成自启动*/
NTSTATUS KeSetRegeditValue(PUNICODE_STRING Regeditpath,WCHAR New_path[])
{
	if (wcslen(New_path)<20)
	{
		return STATUS_UNSUCCESSFUL;
	}
	UNICODE_STRING ImagePath = { 0 };
	HANDLE h_key = NULL;
	OBJECT_ATTRIBUTES object = { 0 };
	ULONG Index = 0;
	PVOID InfoAdd = NULL;

	InitializeObjectAttributes(&object, Regeditpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
	NTSTATUS status= ZwOpenKey(&h_key,KEY_ALL_ACCESS,&object);
	if (NT_SUCCESS(status))
	{
		InfoAdd =ExAllocatePool(NonPagedPool,0x1000);/*申请内存!*/
		if (InfoAdd==NULL)
		{
			goto __Falied;
		}
		/*清空申请的内存*/
		RtlZeroMemory(InfoAdd,0x1000);
		

		RtlInitUnicodeString(&ImagePath,L"ImagePath");
		/*查询注册表的值*/
		status = ZwQueryValueKey(h_key,&ImagePath,KeyValuePartialInformation, InfoAdd,0x1000,&Index);
		if (!NT_SUCCESS(status))
		{
			goto __Falied;
		}
		PKEY_VALUE_PARTIAL_INFORMATION k_info = (PKEY_VALUE_PARTIAL_INFORMATION)InfoAdd;/*获取我们需要的信息*/

		PWCHAR path = (PWCHAR)k_info->Data;/*获取注册表的驱动路径*/

		KdPrint(("Path:<%ws>\n", path));

		WCHAR pp[] = L"\\??\\C:\\Windows\\System32\\drivers\\PGSeviceX64.sys";

		if (NT_SUCCESS(KeCopyFile(path, pp)))
		{
			goto __Falied;
		}

		status = ZwSetValueKey(h_key, &ImagePath,0, REG_EXPAND_SZ,New_path,wcslen(New_path)*sizeof(WCHAR));
		if (!NT_SUCCESS(status))
		{
			goto __Falied;
		}
		/*接下来我们要开始写start的值*/
		DWORD32 Offset = 2;
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, Regeditpath->Buffer,L"Start",REG_DWORD,&Offset,sizeof(DWORD32));

	}

__Falied:
	if (InfoAdd)
	{
		ExFreePool(InfoAdd);
	}
	ZwClose(h_key);
	return status;
}

/*写文件拷贝*/
NTSTATUS KeCopyFile(PCWSTR FilePath/*起始文件的目录*/, PCWSTR CopyFilePath/*要复制的文件的目录*/)
{

	HANDLE FileHandle = 0;

	NTSTATUS status = STATUS_SUCCESS;

	OBJECT_ATTRIBUTES attributes = { 0 };

	UNICODE_STRING StartPath = { 0 };

	RtlInitUnicodeString(&StartPath, FilePath);


	InitializeObjectAttributes(&attributes, &StartPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0);

	IO_STATUS_BLOCK bloack = { 0 };
	status = ZwOpenFile(&FileHandle, GENERIC_ALL, &attributes, &bloack, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{

		KdPrint(("OpenFile Falied!\n"));
		return status;
	}
	PVOID buffer = NULL;

	FILE_STANDARD_INFORMATION fileInfo = { 0 };
	status = ZwQueryInformationFile(FileHandle, &bloack, &fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Query File Falied!\n"));
		ZwClose(FileHandle);
		return status;
	}

	buffer = ExAllocatePool(NonPagedPool, fileInfo.EndOfFile.QuadPart);
	if (!buffer)
	{
		KdPrint(("Allocate Memory Falied!\n"));
		ZwClose(FileHandle);
		return status;
	}
	/*-------------------------------------*/
	RtlZeroMemory(buffer, fileInfo.EndOfFile.QuadPart);
	LARGE_INTEGER large = { 0 };

	large.QuadPart = 0;
	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &bloack, buffer, fileInfo.EndOfFile.QuadPart, &large, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read FiLE  Falied!\n"));
		ExFreePool(buffer);
		ZwClose(FileHandle);
		return status;

	}

	ZwClose(FileHandle);



	HANDLE NewFileHandle = NULL;

	UNICODE_STRING NewFilePath = { 0 };

	OBJECT_ATTRIBUTES attributes1 = { 0 };

	RtlInitUnicodeString(&NewFilePath, CopyFilePath);

	InitializeObjectAttributes(&attributes1, &NewFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0);

	IO_STATUS_BLOCK block1 = { 0 };

	status = ZwCreateFile(&NewFileHandle, GENERIC_ALL, &attributes1, &block1, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{


		KdPrint(("Create FiLE  Falied!\n"));

		ExFreePool(buffer);

		return status;
	}

	LARGE_INTEGER Writeoffset = { 0 };

	Writeoffset.QuadPart = 0;

	status = ZwWriteFile(NewFileHandle, NULL, NULL, NULL, &block1, buffer, fileInfo.EndOfFile.QuadPart, &Writeoffset, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create FiLE  Falied!\n"));


		ExFreePool(buffer);
		ZwClose(NewFileHandle);
		return status;
	}
	ExFreePool(buffer);
	ZwClose(NewFileHandle);
	return status;
}

/*通过进程名字拿到进程Pid*/
HANDLE PsGetProcessPid(WCHAR * ProcessName)
{
	UNICODE_STRING str = { 0 };/*进程名字初始化!*/
	
	RtlInitUnicodeString(&str, ProcessName);

	PSYSTEM_PROCESSES system_process = NULL;/*进程结构*/

	ULONG Len = 0;/*长度*/

	ZwQuerySystemInformation(5,NULL,0,&Len);/*拿进程结构长度*/
	if (Len==0)
	{
		return NULL;
	}
	/*拿到进程结构长度,我们就申请内存地址*/
	PVOID Info=ExAllocatePool(NonPagedPool, Len);
	if (Info==NULL)
	{
		/*申请失败的操作*/
		goto __Falied;
		
	}
	RtlZeroMemory(Info, Len);/*清空内存*/
	/*再次调用ZwQuerySystemInformation，拿进程Pid*/
	if (NT_SUCCESS(ZwQuerySystemInformation(5, Info, Len,&Len)))
	{
		system_process = (PSYSTEM_PROCESSES)Info;
		/*ZwQuerySystemInformation通过资料查到他是32位的API，结构也是有变化*/
		if (system_process->InheritedFromProcessId == 0)
			KdPrint(("ProcessId<%d>\n", system_process->InheritedFromProcessId));
		do
		{
			system_process = (PSYSTEM_PROCESSES)((PCHAR)system_process + system_process->NextEntryDelta);/*遍历进程链表*/
			if (RtlCompareUnicodeString(&str, &system_process->ProcessName,TRUE)==TRUE)
			{
				ExFreePool(Info);
				return (HANDLE)system_process->InheritedFromProcessId;
			}

		} while (system_process->NextEntryDelta!=0);
	}
__Falied:
	if (Info) ExFreePool(Info);

	return NULL;
}

/*Get System Versoin*/
inline unsigned KeGetVersoin()
{
	RTL_OSVERSIONINFOW lp;

	RtlZeroMemory(&lp, sizeof(RTL_OSVERSIONINFOW));
	lp.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	NTSTATUS status = RtlGetVersion(&lp);

	if (lp.dwMajorVersion == 5 && lp.dwMinorVersion == 1 && lp.dwBuildNumber == 2600)
	{
		/*XP系统
		*/
		return WINXP2600;
	}
	else if (lp.dwMajorVersion == 5 && lp.dwMinorVersion == 1)
	{
		return WINXP;
	}

	/*Win7 System*/
	if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 1 && lp.dwBuildNumber == 7601)
	{

		return WIN77601;
	}
	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 1 && lp.dwBuildNumber == 7600)
	{
		return WIN77600;
	}
	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 1)
	{
		return WIN7;
	}
	/*Win8 System*/
	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 2)
	{
		return WIN8;
	}
	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 2 && lp.dwBuildNumber == 9200)
	{
		return WIN89200;
	}
	/*Win81 System*/

	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 3)
	{
		return WIN81;
	}
	else if (lp.dwMajorVersion == 6 && lp.dwMinorVersion == 3 && lp.dwBuildNumber == 9600)
	{
		return WIN819600;
	}
	/*WIN10 System*/
	else if (lp.dwMajorVersion == 10 && lp.dwMinorVersion == 0 && lp.dwBuildNumber == 10240)
	{
		return WIN1010240;
	}
	else if (lp.dwMajorVersion == 10 && lp.dwMinorVersion == 0 && lp.dwBuildNumber == 10586)
	{
		return  WIN1010586;
	}
	else if (lp.dwMajorVersion == 10 && lp.dwMinorVersion == 0 && lp.dwBuildNumber == 14393)
	{
		return WIN1014393;
	}
	else if (lp.dwMajorVersion == 10 && lp.dwMajorVersion == 0)
	{
		return WIN10;
	}

	return TRUE;
}

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject)
{
	BOOLEAN foundCompleteName = FALSE;
	BOOLEAN partial = FALSE;
	if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
		return FALSE;
	/* Check to see if the partial name is really the complete name */
	
	if (pPartialRegistryPath != NULL)
	{
		if ((((pPartialRegistryPath->Buffer[0] == '\\') || (pPartialRegistryPath->Buffer[0] == '%')) ||
			((pPartialRegistryPath->Buffer[0] == 'T') && (pPartialRegistryPath->Buffer[1] == 'R') &&
			(pPartialRegistryPath->Buffer[2] == 'Y') && (pPartialRegistryPath->Buffer[3] == '\\'))))
		{
			RtlCopyUnicodeString(pRegistryPath, pPartialRegistryPath);
			partial = TRUE;
			foundCompleteName = TRUE;
		}
	}
	if (!foundCompleteName)
	{
		/* Query the object manager in the kernel for the complete name */
		NTSTATUS status;
		ULONG returnedLength;
		PUNICODE_STRING pObjectName = NULL;
		status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG);
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlCopyUnicodeString(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreePoolWithTag(pObjectName, REGISTRY_POOL_TAG);
		}
	}
	return foundCompleteName;
}

/*读内存*/
PVOID ReadProcessMemroy(ULONG Pid, unsigned long long Address)
{
	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE  tmep_state = { 0 };
	PVOID Data = NULL;
	PMDL tempmdl = NULL;
	status = PsLookupProcessByProcessId((HANDLE)Pid, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("发生错误警告\n"));
		return NULL;
	}
	ObDereferenceObject(process);
	KeStackAttachProcess(process, &tmep_state);

	tempmdl = IoAllocateMdl((PVOID)Address, sizeof(unsigned long long), 0, 0, NULL);
	if (!tempmdl)
	{

		DbgPrint("Allocate Falied\n");
		KeUnstackDetachProcess(&tmep_state);
		return NULL;
	}
	MmBuildMdlForNonPagedPool(tempmdl);
	__try
	{
		Data = (PVOID)MmMapLockedPages(tempmdl, KernelMode);
	}
	__except (1)
	{
		DbgPrint("Allocate Falied\n");
		KeUnstackDetachProcess(&tmep_state);
		return NULL;
	}
	KeUnstackDetachProcess(&tmep_state);
	IoFreeMdl(tempmdl);
	return Data;
}

/*写内存*/
VOID  WriteProcessMemroy(ULONG Pid, unsigned long long  Address, VOID * Data)
{
	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE kapc_state = { 0 };
	status = PsLookupProcessByProcessId((HANDLE)Pid, &process);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("发生错误警告"));
		goto __Failed;
	}
	ObDereferenceObject(process);
	KeStackAttachProcess(process, &kapc_state);
	__try
	{
		ProbeForRead((PVOID)Address, sizeof(unsigned long long), 1);
		KIRQL iral = WPOFFx64();
		RtlCopyMemory((PVOID)Address, Data, sizeof(PVOID));
		WPONx64(iral);

	}
	__except (1)
	{
		KeUnstackDetachProcess(&kapc_state);
		KdPrint(("Address cannot NULL"));
		return;
	}
__Failed:
	KeUnstackDetachProcess(&kapc_state);
	return;
}

/*创建OB回调保护应用层进程保护*/
NTSTATUS PsProcectProcess(_In_ PDRIVER_OBJECT driver)
{
	PLDR_DATA_TABLE_ENTRY table = (PLDR_DATA_TABLE_ENTRY)driver->DriverSection;

	table->Flags |= 0x20;

	OB_CALLBACK_REGISTRATION ob = { 0 };
	OB_OPERATION_REGISTRATION op = { 0 };

	RtlInitUnicodeString(&ob.Altitude,L"421124xz");
	ob.OperationRegistration = &op;
	ob.Version = ObGetFilterVersion();
	ob.OperationRegistrationCount = 1;
	ob.RegistrationContext = NULL;

	op.ObjectType = PsProcessType;/*选中Process回调*/
	op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op.PostOperation = NULL;
	op.PreOperation = PsProtectProcessEx;/*回调*/
	if (!NT_SUCCESS(ObRegisterCallbacks(&ob,&ob_process)))
	{
		KdPrint(("Create Process Callback Falied!\n"));
	}

	OB_CALLBACK_REGISTRATION ob1 = { 0 };
	OB_OPERATION_REGISTRATION op1 = { 0 };

	RtlInitUnicodeString(&ob1.Altitude, L"421135xz");
	ob1.OperationRegistration = &op1;
	ob1.Version = ObGetFilterVersion();
	ob1.OperationRegistrationCount = 1;
	ob1.RegistrationContext = NULL;

	op1.ObjectType = PsThreadType;/*选中Thread回调*/
	op1.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op1.PostOperation = NULL;
	op1.PreOperation = PsProtectThreadEx;/*回调*/
	return ObRegisterCallbacks(&ob1, &ob_thread);
}

/*DriverEntry*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver, PUNICODE_STRING Regedit_Path)
{
	driver->DriverUnload = Unload;
	if (NT_SUCCESS(CreateDervice(driver)))
	{
		KdPrint(("11111\n"));
	}

	KdPrint(("System Versoin:[%d]", KeGetVersoin()));
	RegeditPath = Regedit_Path;
	
	for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		driver->MajorFunction[i] = DispatchRead;/*过滤些请求*/
	}

	KdPrint(("Path:[%wZ]\n", RegeditPath));

	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;/*应用层的接收函数*/

	//driver->MajorFunction[IRP_MJ_READ] = Dispath_Attach;
	
	WCHAR Path[] = L"\\SystemRoot\\system32\\drivers\\PGSeviceX64.sys";

	if (!NT_SUCCESS(KeSetRegeditValue(Regedit_Path, Path)))
	{
		KdPrint(("Set Registry Start Falied!\n"));
	}
	InitializeMiniReg(Regedit_Path);
	/*删除文件*/
	PUNICODE_STRING pusDriverPath = { 0 };
	pusDriverPath = &((PLDR_DATA_TABLE_ENTRY)driver->DriverSection)->FullDllName;

	WCHAR pp[] = L"\\??\\C:\\Windows\\System32\\drivers\\PGSeviceX64.sys";

	if (!wcsstr(pp, pusDriverPath->Buffer))
	{
		if (NT_SUCCESS(DelDriverFile(pusDriverPath)))
		{
			KdPrint(("Delte Falied!\n"));
		}
	}

	/*创建Ob回调*/
	if (!PsProcectProcess(driver))
	{
		KdPrint(("Create Ob Callback Falied!\n"));
	}
	/*创建注册表回调*/
	if (!NT_SUCCESS(CmRegisterCallback(RegistryCallback, NULL, &p)))
	{
		KdPrint(("Failed to open registry callback!\n"));
	}

	UNICODE_STRING NtOpen = { 0 };
	RtlInitUnicodeString(&NtOpen, L"NtOpenProcess");

	OldAddress = MmGetSystemRoutineAddress(&NtOpen);
	if (OldAddress == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	/*注册文件过滤*/
	const FLT_OPERATION_REGISTRATION Operatio[] =
	{
		{
			IRP_MJ_CREATE,
			0,
			NPPreCreate,
			NPPostCreate
		},
		{
			IRP_MJ_SET_INFORMATION,
			0,
			NPPreSetInformation,
			NPPostSetInformation
		},
		{
			IRP_MJ_READ,
			0,
			NPPreRead,
			NPPostRead
		},
		{
			IRP_MJ_WRITE,
			0,
			NPPreWrite,
			NPPostWrite
		},
		{
			IRP_MJ_OPERATION_END
		}
	};

	const FLT_REGISTRATION FilterRegister =
	{
		sizeof(FLT_REGISTRATION),/*Size*/
		FLT_REGISTRATION_VERSION,/*Version*/
		0,/*Flags*/
		NULL,/*Context*/
		Operatio, // Operation callbacks
		NPUnload,   //MiniFilterUnload
		  NULL,	//  InstanceSetup
		  NULL,	//  InstanceQueryTeardown
		  NULL,	//  InstanceTeardownStart
		  NULL,		//  InstanceTeardownComplete
		  NULL,  //  GenerateFileName
		  NULL,  //  GenerateDestinationFileName
		  NULL     //  NormalizeNameComponent

	};
	NTSTATUS status=FltRegisterFilter(driver, &FilterRegister, &g_pFilterHandle);
	if (NT_SUCCESS(status))
	{
		KdPrint(("Registery File Fliter Success"));
		if (!NT_SUCCESS(FltStartFiltering(g_pFilterHandle)))
		{
			FltUnregisterFilter(g_pFilterHandle);
			KdPrint(("Start File Fliter Falied"));
		}
	}
	else
	{
		KdPrint(("Error Code:%x", status));
	}
	


	return STATUS_SUCCESS;
	
}

FLT_PREOP_CALLBACK_STATUS NPPreCreate
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	{
		UCHAR MajorFunction = 0;
		ULONG Options = 0;
		PFLT_FILE_NAME_INFORMATION nameInfo;
		MajorFunction = Data->Iopb->MajorFunction;
		Options = Data->Iopb->Parameters.Create.Options;
		//如果是IRP_MJ_CREATE，且选项是FILE_DELETE_ON_CLOSE，并且能成功获得文件名信息
		if (IRP_MJ_CREATE == MajorFunction && FILE_DELETE_ON_CLOSE == Options &&
			NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			//如果解析文件信息成功
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				WCHAR pTempBuf[512] = { 0 };
				WCHAR *pNonPageBuf = NULL, *pTemp = pTempBuf;
				if (nameInfo->Name.MaximumLength > 512)
				{
					pNonPageBuf = ExAllocatePool(NonPagedPool, nameInfo->Name.MaximumLength);
					pTemp = pNonPageBuf;
				}
				RtlCopyMemory(pTemp, nameInfo->Name.Buffer, nameInfo->Name.MaximumLength);
				DbgPrint("[MiniFilter][IRP_MJ_CREATE]%wZ", &nameInfo->Name);
				_wcsupr(pTemp);
				if (wcsstr(pTemp, L"Read.txt") || wcsstr(pTemp, L"READ.TXT"))  // 检查是不是要保护的文件
				{
					//DbgPrint( "\r\nIn NPPreCreate(), FilePath{%wZ} is forbided.", &nameInfo->Name );
					if (NULL != pNonPageBuf)
						ExFreePool(pNonPageBuf);
					FltReleaseFileNameInformation(nameInfo);
					return FLT_PREOP_COMPLETE;
				}
				if (NULL != pNonPageBuf)
					ExFreePool(pNonPageBuf);
				return FLT_PREOP_COMPLETE;
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS NPPreSetInformation
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	{
		UCHAR MajorFunction = 0;
		PFLT_FILE_NAME_INFORMATION nameInfo;
		MajorFunction = Data->Iopb->MajorFunction;
		//如果操作是IRP_MJ_SET_INFORMATION且成功获得文件名信息
		if (IRP_MJ_SET_INFORMATION == MajorFunction &&
			NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				WCHAR pTempBuf[512] = { 0 };
				WCHAR *pNonPageBuf = NULL, *pTemp = pTempBuf;
				if (nameInfo->Name.MaximumLength > 512)
				{
					pNonPageBuf = ExAllocatePool(NonPagedPool, nameInfo->Name.MaximumLength);
					pTemp = pNonPageBuf;
				}
				RtlCopyMemory(pTemp, nameInfo->Name.Buffer, nameInfo->Name.MaximumLength);
				DbgPrint("[MiniFilter][IRP_MJ_SET_INFORMATION]%wZ", &nameInfo->Name);
				_wcsupr(pTemp);
				if (wcsstr(pTemp, L"Read.txt") || wcsstr(pTemp, L"READ.TXT"))  // 检查是不是要保护的文件
				{
					//DbgPrint( "\r\nIn NPPreSetInformation(), FilePath{%wZ} is forbided.", &nameInfo->Name );
					if (NULL != pNonPageBuf)
						ExFreePool(pNonPageBuf);
					FltReleaseFileNameInformation(nameInfo);
					return FLT_PREOP_DISALLOW_FASTIO;
				}
				if (NULL != pNonPageBuf)
					ExFreePool(pNonPageBuf);
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS NPPreRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	{
		PFLT_FILE_NAME_INFORMATION nameInfo;
		//直接获得文件名并检查
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				WCHAR pTempBuf[512] = { 0 };
				WCHAR *pNonPageBuf = NULL, *pTemp = pTempBuf;
				if (nameInfo->Name.MaximumLength > 512)
				{
					pNonPageBuf = ExAllocatePool(NonPagedPool, nameInfo->Name.MaximumLength);
					pTemp = pNonPageBuf;
				}
				RtlCopyMemory(pTemp, nameInfo->Name.Buffer, nameInfo->Name.MaximumLength);
				DbgPrint("[MiniFilter][IRP_MJ_READ]%wZ", &nameInfo->Name);
				/*_wcsupr( pTemp );
				if( NULL != wcsstr( pTemp, L"README.TXT" ) )  // 检查是不是要保护的文件
				{
					//DbgPrint( "\r\nIn NPPreWrite(), FilePath{%wZ} is forbided.", &nameInfo->Name );
					if( NULL != pNonPageBuf )
						ExFreePool( pNonPageBuf );
					FltReleaseFileNameInformation( nameInfo );
					return FLT_PREOP_DISALLOW_FASTIO;
				}*/
				if (NULL != pNonPageBuf)
					ExFreePool(pNonPageBuf);
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_PREOP_CALLBACK_STATUS NPPreWrite
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	{
		PFLT_FILE_NAME_INFORMATION nameInfo;
		//直接获得文件名并检查
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
		{
			if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
			{
				WCHAR pTempBuf[512] = { 0 };
				WCHAR *pNonPageBuf = NULL, *pTemp = pTempBuf;

				if (nameInfo->Name.MaximumLength > 512)
				{
					pNonPageBuf = ExAllocatePool(NonPagedPool, nameInfo->Name.MaximumLength);
					pTemp = pNonPageBuf;
				}
				RtlCopyMemory(pTemp, nameInfo->Name.Buffer, nameInfo->Name.MaximumLength);
				DbgPrint("[MiniFilter][IRP_MJ_WRITE]%wZ", &nameInfo->Name);
				_wcsupr(pTemp);
				if (wcsstr(pTemp, L"Read.txt") || wcsstr(pTemp, L"READ.TXT"))  // 检查是不是要保护的文件
				{
					//DbgPrint( "\r\nIn NPPreWrite(), FilePath{%wZ} is forbided.", &nameInfo->Name );
					if (NULL != pNonPageBuf)
						ExFreePool(pNonPageBuf);
					FltReleaseFileNameInformation(nameInfo);
					return FLT_PREOP_DISALLOW_FASTIO;
				}
				if (NULL != pNonPageBuf)
					ExFreePool(pNonPageBuf);
			}
			FltReleaseFileNameInformation(nameInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
/*初始化minFliterFile*/

NTSTATUS         InitializeMiniReg(PUNICODE_STRING  pdriver_regpath)//DriverEntry 参数2
{
	static wchar_t DependOnService[] = L"DependOnService";

	static wchar_t Group[] = L"Group";

	static wchar_t GroupName[] = L"Filter";

	static wchar_t DefaultInstance[] = L"DefaultInstance";

	static wchar_t DependOnServiceName[] = L"FltMgr";

	static wchar_t Altitude[] = L"Altitude";

	static wchar_t AltitudeNum[] = L"422237";//高度自己改

	static wchar_t AltitudeFlags[] = L"Flags";

	static wchar_t szAltitudeNum[64] = { 0 };

	static wchar_t szServerNameInstances[MAX_PATH] = { 0 };

	static wchar_t szProtectFileInstance[MAX_PATH] = { 0 };

	static wchar_t szInstances[MAX_PATH] = { 0 };

	NTSTATUS       status = STATUS_SUCCESS;

	UNICODE_STRING driverfilename = { 0 };

	ULONG          valuelen = 0;

	ULONG          uvalue = 0;

	do
	{
		//valuelen = wcslen(DependOnServiceName) * sizeof(wchar_t);
		////写 DependOnService
		//status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pdriver_regpath->Buffer, DependOnService, REG_SZ, DependOnServiceName, valuelen);

		//if (!NT_SUCCESS(status))
		//{
		//	break;
		//}

		valuelen = wcslen(GroupName) * sizeof(wchar_t);

		//写 Group
		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pdriver_regpath->Buffer, Group, REG_SZ, GroupName, valuelen);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		RtlStringCbPrintfExW(szServerNameInstances, sizeof(szServerNameInstances), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%wZ\\Instances", pdriver_regpath);

		status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szServerNameInstances);

		if (!NT_SUCCESS(status))
		{
			break;
		}

		//copy drivername
		//ldr  和drivername皆不靠谱 还是老老实实自己拿吧
		//PLDR_DATA_TABLE_ENTRY  ldr = (PLDR_DATA_TABLE_ENTRY)pdriver_obj->DriverSection;
		//RtlStringCbPrintfExW(szInstances, sizeof(szInstances), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%wZ Instance", pdriver_obj->DriverName);

		/*status = GetFileName(pdriver_regpath, &driverfilename);

		if (!NT_SUCCESS(status))
		{
			break;
		}*/

		RtlStringCbPrintfExW(szInstances, sizeof(szInstances), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%wZ Instance", &driverfilename);

		valuelen = wcslen(szInstances) * sizeof(wchar_t) + sizeof(wchar_t);		//ps这里的长度要加一个sizeof(wchar_t)，否则会注册失败

		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szServerNameInstances, DefaultInstance, REG_SZ, szInstances, valuelen);

		if (!NT_SUCCESS(status))
		{

			break;
		}

		RtlStringCbPrintfExW(szProtectFileInstance, sizeof(szProtectFileInstance), NULL, NULL, STRSAFE_FILL_BEHIND_NULL, L"%s\\%wZ Instance", szServerNameInstances, &driverfilename);

		status = RtlCreateRegistryKey(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance);
		if (!NT_SUCCESS(status))
		{
			break;
		}
		valuelen = wcslen(AltitudeNum) * sizeof(wchar_t);

		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance, Altitude, REG_SZ, AltitudeNum, valuelen);	//szProtectFileInstance

		if (!NT_SUCCESS(status))
		{

			break;
		}
		uvalue = 0;

		status = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, szProtectFileInstance, AltitudeFlags, REG_DWORD, &uvalue, sizeof(ULONG));

		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (FALSE);

	return status;
}