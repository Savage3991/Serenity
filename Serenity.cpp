#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <utility>

struct roblox_t {
	HANDLE hRoblox;
	DWORD pid;
	DWORD tid;

	PVOID win32uBase;
	PVOID robloxBase;
};

roblox_t GetRobloxHandle() {
	roblox_t robloxInfo{};

	HWND rbx = FindWindowA(NULL, "Roblox");

	DWORD pid = 0;
	DWORD tid = GetWindowThreadProcessId(rbx, &pid);

	return roblox_t{ OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), pid, tid };
}

bool IsInvalid(HANDLE h) {
	return h == INVALID_HANDLE_VALUE;
}

bool GetModuleBases(roblox_t& robloxInfo) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, robloxInfo.pid);
	if (IsInvalid(hSnap)) {
		std::printf("INVALID SNAPSHOT!\n");
		return false;
	}

	MODULEENTRY32 currentModule{};
	currentModule.dwSize = sizeof(currentModule);

	if (Module32First(hSnap, &currentModule)) {
		do {
			if (!std::strcmp(currentModule.szModule, "win32u.dll")) {
				robloxInfo.win32uBase = currentModule.modBaseAddr;
			}
			else if (!std::strcmp(currentModule.szModule, "RobloxPlayerBeta.exe")) {
				robloxInfo.robloxBase = currentModule.modBaseAddr;
			}
		} while (Module32Next(hSnap, &currentModule));
	}
	else {
		std::printf("MODULE ITERATION FAILED!\n");
	}

	CloseHandle(hSnap);
	return robloxInfo.robloxBase && robloxInfo.win32uBase;
}

#include "Header.h"

#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#pragma runtime_checks("", off)
#pragma optimize("", off)
void ultra_skibidi(int a1, void* a2) {

	/*struct Shared {
		void* msg_ptr;
		
	};*/

	auto pShared = reinterpret_cast<Shared*>(a2);

	pShared->checkpoint = 1;

	BYTE* pBase = pShared->pBase;

	pShared->checkpoint = 2;

	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	pShared->checkpoint = 3;
	auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)>(pBase + pOpt->AddressOfEntryPoint);

	pShared->checkpoint = 4;
	auto _LoadLibraryA = pShared->LoadLibraryA;

	pShared->checkpoint = 5;
	auto _GetProcAddress = pShared->GetProcAddress;

	pShared->checkpoint = 6;
	auto _GetCurrentThreadId = pShared->GetCurrentThreadId;

	pShared->checkpoint = 7;
	auto _RtlAddFunctionTable = RtlAddFunctionTable;

	pShared->checkpoint = 8;
	auto _GetModuleHandleA = GetModuleHandleA;

	pShared->checkpoint = 9;

	uintptr_t LocationDelta = (uintptr_t)pBase - pOpt->ImageBase;
	if (LocationDelta) {
		IMAGE_DATA_DIRECTORY RelocDir = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (RelocDir.Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + RelocDir.VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + RelocDir.Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += LocationDelta;
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	pShared->checkpoint = 2;

#pragma region FIXING IMPPORTS
	auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pShared->pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (pImportDesc->Name) {
		char* szMod = reinterpret_cast<char*>(pShared->pBase + pImportDesc->Name);

		HINSTANCE hDll = _LoadLibraryA(szMod);
		if (!hDll) {}
		UINT_PTR* pThunkRef = reinterpret_cast<UINT_PTR*>(pShared->pBase + pImportDesc->OriginalFirstThunk);
		FARPROC* pFuncRef = reinterpret_cast<FARPROC*>(pShared->pBase + pImportDesc->FirstThunk);
		if (!pThunkRef) { pThunkRef = reinterpret_cast<UINT_PTR*>(pFuncRef); }
		for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
			if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
				*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<const char*>(IMAGE_ORDINAL(*pThunkRef)));
			}
			else {
				auto* thunkData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pShared->pBase + (*pThunkRef));
				*pFuncRef = _GetProcAddress(hDll, thunkData->Name);
			}
		}
		++pImportDesc;
	}

#pragma endregion

	pShared->checkpoint = 3;

	auto size = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	if (size)
	{
		auto* pExceptionHandlers = reinterpret_cast<RUNTIME_FUNCTION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		auto EntryCount = size / sizeof(RUNTIME_FUNCTION);
		_RtlAddFunctionTable(pExceptionHandlers, MDWD(EntryCount), (DWORD64)pBase);
	}

#pragma region TLS CALLBACKS
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* TlsData = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* CallbackArray = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(TlsData->AddressOfCallBacks);
		while (CallbackArray && *CallbackArray) {
			PIMAGE_TLS_CALLBACK Callback = *CallbackArray;
			Callback(reinterpret_cast<void*>(pBase), DLL_PROCESS_ATTACH, nullptr);
		}
	}

#pragma endregion

	pShared->checkpoint = 4;

#pragma region DllMain Calling

	_DllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, (LPVOID)pOpt->SizeOfImage);

#pragma endregion

	pShared->checkpoint = 5;

	//MessageBoxA(NULL, (LPCSTR)gubaduba->msg_ptr, (LPCSTR)gubaduba->titel_ptr, MB_OK);

	//auto sigma = reinterpret_cast<Shared*>(a2);

	//reinterpret_cast<void(__fastcall*)(int, const char*, ...)>( gubaduba->print )(0, (const char*)gubaduba->msg_ptr);

	//print(0, (const char*)gubaduba->msg_ptr);

}

void CallPrintFunction(roblox_t& robloxInfo) {

	auto ntdll = LoadLibraryA("ntdll.dll");

	FILE* f = fopen("C:\\Users\\mfglg\\source\\repos\\TestDLL\\x64\\Release\\TestDLL.dll", "rb");
	if (f == NULL) {
		return;
	}

	fseek(f, 0, SEEK_END);
	std::size_t s = ftell(f);
	rewind(f);

	void* pSrcData = malloc(s);
	if (pSrcData == NULL) {
		return;
	}

	if (fread(pSrcData, 1, s, f) < s) {
		return;
	}

	auto* pOldNtHeader = (IMAGE_NT_HEADERS*)((uintptr_t)pSrcData + ((IMAGE_DOS_HEADER*)pSrcData)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = &pOldNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;

	auto target_base = (BYTE*)(VirtualAllocEx(robloxInfo.hRoblox, NULL, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (target_base == NULL) {

		return;
	}
	if (!WriteProcessMemory(robloxInfo.hRoblox, target_base, pSrcData, 0x1000, NULL)) {

		return;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(robloxInfo.hRoblox, target_base + pSectionHeader->VirtualAddress, (void*)((uintptr_t)pSrcData + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL)) {

				return;
			}
		}
	}

	std::uintptr_t baseText = (std::uintptr_t)robloxInfo.win32uBase + 0x1000;
	std::uintptr_t printFunction = (std::uintptr_t)robloxInfo.robloxBase + 0x1516AB0;

	unsigned char shellcode[] = { 0x48, 0xB8, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x48, 0xBA, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0xB8, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xFF, 0xE0 };
	
	/*
	const char* myMessage2 = "cg is so special :heart:";
	void* myMessagePtr2 = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
	WriteProcessMemory(robloxInfo.hRoblox, myMessagePtr2, myMessage2, std::strlen(myMessage2), nullptr); // Write our message into message memorys

	const char* myMessage = "cg is so bomboclat drool";
	void* myMessagePtr = VirtualAllocEx(robloxInfo.hRoblox, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
	WriteProcessMemory(robloxInfo.hRoblox, myMessagePtr, myMessage, std::strlen(myMessage), nullptr); // Write our message into message memorys
	*/

	// Here is the injection logic
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, robloxInfo.tid);
	std::printf("Hijacking thread: %d\n", robloxInfo.tid);

	DWORD result = SuspendThread(hThread);
	if (result == -1) {
		std::printf("Failed to suspend thread!\n");
	}
	else {
		void* pShared = VirtualAllocEx(robloxInfo.hRoblox, NULL, sizeof(Shared), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pShared == NULL) {
			return;
		}

		void* pShellcode = VirtualAllocEx(robloxInfo.hRoblox, NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pShellcode == NULL) {
			return;
		}
		if (!WriteProcessMemory(robloxInfo.hRoblox, pShellcode, (void*)ultra_skibidi, 0x2000, NULL)) {
			return;
		}

		Shared data;
		data.pBase = target_base;
		data.checkpoint = 0;
		data.dwDllSize = s;

		data.LoadLibraryA = LoadLibraryA;
		data.GetProcAddress = GetProcAddress;
		data.GetCurrentThreadId = GetCurrentThreadId;
		data.process_id = robloxInfo.pid;

		data.LdrLockLoaderLock = reinterpret_cast<LdrLockLoaderLock_t>(
			GetProcAddress(ntdll, "LdrLockLoaderLock"));

		data.LdrUnlockLoaderLock = reinterpret_cast<LdrUnlockLoaderLock_t>(
			GetProcAddress(ntdll, "LdrUnlockLoaderLock"));

		data.RtlAllocateHeap = reinterpret_cast<RtlAllocateHeap_t>(
			GetProcAddress(ntdll, "RtlAllocateHeap"));

		printf("RtlAllocateHeap: %p\n", data.RtlAllocateHeap);

		data.RtlFreeHeap = reinterpret_cast<RtlFreeHeap_t>(
			GetProcAddress(ntdll, "RtlFreeHeap"));
		printf("RtlFreeHeap: %p\n", data.RtlFreeHeap);

		data.LdrpTlsList = reinterpret_cast<LIST_ENTRY*>(
			GetProcAddress(ntdll, "LdrpTlsList"));
		printf("LdrpTlsList: %p\n", data.LdrpTlsList);

		data.NtCurrentTeb = NtCurrentTeb;

		data.AddVectoredExceptionHandler = reinterpret_cast<AddVectoredExceptionHandler_t>(&AddVectoredExceptionHandler);
		printf("AddVectoredExceptionHandler: %p\n", data.AddVectoredExceptionHandler);

		//data.pHyperion = reinterpret_cast<void*>(this->hyperion_base);

		data.InternalMapperPage = reinterpret_cast<std::uintptr_t>(pShellcode);
		data.InternalMapperSize = 0x2000;

		GetSystemTimeAsFileTime(&data.system_time);
		QueryPerformanceCounter(&data.performance_count);

		//data.msg_ptr = myMessagePtr;
		//data.titel_ptr = myMessagePtr2;
		//data.print = printFunction;
		//data.print_address = printFunction;

		if (!WriteProcessMemory(robloxInfo.hRoblox, pShared, &data, sizeof(Shared), NULL)) {
			return;
		}





		CONTEXT threadCtx{};
		threadCtx.ContextFlags = CONTEXT_ALL;

		if (!GetThreadContext(hThread, &threadCtx)) {
			std::printf("Failed to get thread context!\n");
			CloseHandle(hThread);
			return;
		}

		// Retrieve old return value off stack (remember the thread is suspended so it has to have a return here)
		std::uintptr_t oldReturnValue = 0;
		ReadProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &oldReturnValue, sizeof(oldReturnValue), nullptr);

		// Replace return to our hook
		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)threadCtx.Rsp, &baseText, sizeof(baseText), nullptr);

		*(std::uintptr_t*)(&shellcode[2]) = (uintptr_t)pShellcode;
		*(std::uint32_t*)(&shellcode[11]) = 1;
		*(std::uintptr_t*)(&shellcode[17]) = (std::uintptr_t)pShared;
		*(std::uintptr_t*)(&shellcode[29]) = oldReturnValue;

		WriteProcessMemory(robloxInfo.hRoblox, (PVOID)baseText, shellcode, sizeof(shellcode), nullptr); // Write the code payload for shellcode.
		ResumeThread(hThread);

		Shared internal;
		internal.checkpoint = 0;
		while (internal.checkpoint != 50) {
			Sleep(1);
			printf("waiting for internal mapper to finish: %d...\n", internal.checkpoint);
			ReadProcessMemory(robloxInfo.hRoblox, pShared, &internal, sizeof(Shared), NULL);
		}
		BYTE* empty_buffer = (BYTE*)malloc(1024 * 1024 * 20);
		if (empty_buffer == nullptr) {}
		memset(empty_buffer, 0, 1024 * 1024 * 20);

		WriteProcessMemory(robloxInfo.hRoblox, target_base, empty_buffer, 0x1000, nullptr);

	}

	CloseHandle(hThread);
}

int main()
{
	std::printf("Loading Serenity!\n");
	roblox_t robloxInfo = GetRobloxHandle();

	if (IsInvalid(robloxInfo.hRoblox)) {
		std::printf("Failed to get Roblox.\n");
		return 0;
	}

	std::printf("Roblox PID: %d\n", robloxInfo.pid);

	if (!GetModuleBases(robloxInfo)) {
		std::printf("Failed to find addresses of modules!\n");

		CloseHandle(robloxInfo.hRoblox);
		return 0;
	}

	std::printf("win32u.dll: 0x%p\n", robloxInfo.win32uBase);
	std::printf("RobloxPlayerBeta.exe: 0x%p\n", robloxInfo.robloxBase);

	CallPrintFunction(robloxInfo);
	CloseHandle(robloxInfo.hRoblox);
	return 0;
}
