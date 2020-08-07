#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>

#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef UNICODE
#define UNICODE
#endif


#define DLLPATH "hack_dll.dll"

HANDLE GetProcProcess(LPCWSTR name);
void printError(const TCHAR* msg);
BOOL InjectLib(HANDLE handle, LPCSTR LibPath);
BOOL GetProcIAT(HANDLE handle);

int
main()
{
	LPWSTR procName = (LPWSTR) malloc (64 * sizeof(WCHAR));
	lstrcpyW(procName, TEXT("hl.exe"));

	CHAR *path = (CHAR *)malloc(128 * sizeof(CHAR));
	strcpy_s(path, 41, DLLPATH);

	HANDLE hl = GetProcProcess(procName);

	if (hl == NULL) {

		printf("failed");

	} 

	BOOL ret = InjectLib(hl, path);

	printf("%d", ret);

	// GetProcIAT(hl);
	CloseHandle(hl);
	return 0;
}

/************************************
// function: GetProcProcess
// ÕÒµ½²¢»ñÈ¡ÓÎÏ·½ø³Ì¾ä±ú,´òÓ¡½ø³ÌÐÅ
// Ï¢
 ************************************/
HANDLE 
GetProcProcess(LPCWSTR name)
{
	int isFound = 0;
	HANDLE hProcessSnap = NULL;
	HANDLE handle = NULL;
	PROCESSENTRY32 pe32;

	//ÅÄÉã½ø³Ì¿ìÕÕ
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{

		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(NULL);

	}

	//ÉèÖÃ½á¹¹Ìå´óÐ¡
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//³¢ÊÔ»ñÈ¡µÚÒ»¸ö½ø³ÌµÄÐÅÏ¢
	if (!Process32First(hProcessSnap, &pe32))
	{

		printError(TEXT("Process32First")); 
		CloseHandle(hProcessSnap);
		return(NULL);

	}

	//Ñ­»·»ñÈ¡ÐÅÏ¢Ö±µ½ÕÒµ½ÓÎÏ·½ø³Ì£¬»ñÈ¡½ø³Ì¾ä±ú£¬´òÓ¡½ø³ÌÐÅÏ¢
	do
	{

		if (lstrcmpW(pe32.szExeFile, name))
		{

			continue;

		}

		handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (handle == NULL)
			printError(TEXT("OpenProcess"));

		//´òÓ¡ÐÅÏ¢
		_tprintf(TEXT("\n"));
		_tprintf(TEXT(" Opening Game Process: \n"));
		_tprintf(TEXT(" Process Name    = %ws \n"), pe32.szExeFile);
		_tprintf(TEXT(" Process ID      = 0x%08X \n"), pe32.th32ProcessID);
		_tprintf(TEXT("\n"));

		isFound = 1;
		break;

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	//·µ»Ø½ø³Ì¾ä±ú
	if (isFound)
	{

		return handle;

	} else {

		return NULL;

	}
}


/************************************
// function: InjectLib
// HANDLE _IN_ handle           Ä¿±ê½ø³Ì
// LPCSTR _IN_ LibPath      Ô´¶¯Ì¬¿â 
// ×¢Èë¶¯Ì¬¿âµ½½ø³Ì
 ************************************/
BOOL 
InjectLib(HANDLE handle, LPCSTR LibPath)
{
	LPCSTR pFuncName = "LoadLibraryA";

	//ÅÐ¶ÏÓÎÏ·½ø³Ì¾ä±ú×´Ì¬
	if (handle == NULL)
	{

		_tprintf(TEXT(" ERROR: Open Process Failed \n"));
		return (FALSE);

	}

	//Ô¶³ÌÉêÇëÄÚ´æ¿Õ¼ä
	SIZE_T pathSize = strlen(LibPath) + sizeof(CHAR);
	PVOID PathAddr = VirtualAllocEx(handle, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);

	if (PathAddr == NULL)
	{

		printError(TEXT("VirtualAllocEx"));
		//_tprintf(_TEXT(" ERROR: Alloc Memory Failed \n"));
		return (FALSE);

	}

	//Ð´ÈëdllÂ·¾¶µ½Ô¶³ÌÄÚ´æ
	DWORD WriteNum;
	BOOL ret = WriteProcessMemory(handle, PathAddr, LibPath, pathSize, &WriteNum);

	if (false == ret)
	{

		printError(TEXT("WriteProcessMemory"));
		return (FALSE);

	}

	//»ñÈ¡kernel32 dll¾ä±ú
	HMODULE kernel32 = GetModuleHandleW(TEXT("kernel32.dll"));

	if (kernel32 == NULL)
	{

		printError(TEXT("GetModuleHandleW"));
		return (FALSE);

	}

	//»ñÈ¡LoadLibraryAº¯ÊýµØÖ·
	FARPROC pFuncAddr = GetProcAddress(kernel32, pFuncName);

	if (pFuncAddr == NULL)
	{

		printError(TEXT("GetProcAddress"));
		return (FALSE);

	}

	//´´½¨Ô¶³ÌÏß³Ì
	HANDLE RmtThrd = CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncAddr, PathAddr, 0, NULL);

	if (RmtThrd == NULL)
	{

		printError(TEXT("CreateRemoteThread"));
		return (FALSE);

	}

	WaitForSingleObject(RmtThrd, INFINITE);
	CloseHandle(RmtThrd);

	return (TRUE);
}

void 
printError(const TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL
	);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;

	while ((*p > 31) || (*p == 9)) ++p;

	do { *p-- = 0; } while ((p >= sysMsg) && ((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}
