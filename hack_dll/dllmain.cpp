#include "stdafx.h"

void modify_mem(PVOID s, PVOID d);
void restore_mem(BYTE *src, PVOID dst, int size);
void debug_byte(const BYTE *out, int mode, int size = 4);


namespace HackModule {

	HMODULE hack_module_handle = nullptr;
	HMODULE opendl32_module_handle = nullptr;
	PVOID hack_glbegin_proc_handle = nullptr;
	PVOID opengl32_glbegin_proc_handle = nullptr;
	PVOID opengl32_gldisable_proc_handle = nullptr;

	HMODULE hw = nullptr;
	BYTE *save = nullptr;
	HANDLE proc_handle = nullptr;

	std::mutex mtx;

}


BOOL APIENTRY 
DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	//处理DLL信号
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;

	HackModule::proc_handle = GetCurrentProcess();
	HackModule::hack_module_handle = GetModuleHandle(TEXT("Project1.dll"));
	HackModule::opendl32_module_handle = GetModuleHandle(TEXT("opendl32_module_handle.dll"));

	if (HackModule::hack_module_handle == NULL)
	{

		debug_byte((const BYTE *)"Get Project Handle Failed!", DEBUG_OUT);
		goto falseRet;

	}

	if (HackModule::opendl32_module_handle == NULL)
	{

		debug_byte((const BYTE *)"Get opendl32_module_handle Handle Failed!", DEBUG_OUT);
		goto falseRet;

	}

	HackModule::hack_glbegin_proc_handle = GetProcAddress(HackModule::hack_module_handle, "_myGlBegin@4");
	HackModule::opengl32_glbegin_proc_handle = GetProcAddress(HackModule::opendl32_module_handle, "glBegin");
	HackModule::opengl32_gldisable_proc_handle = GetProcAddress(HackModule::opendl32_module_handle, "glDisable");

	if (HackModule::hack_glbegin_proc_handle == NULL)
	{

		debug_byte((const BYTE *)"Get Function Address Failed!", DEBUG_OUT);
		goto falseRet;

	}

	if (HackModule::opengl32_glbegin_proc_handle == NULL)
	{

		debug_byte((const BYTE *)"Get opengl32_glbegin_proc_handle Address Failed!", DEBUG_OUT);
		goto falseRet;

	}

	debug_byte((const BYTE *)"SUCCESS: Loading Completed!", DEBUG_OUT);

	if (HackModule::save != nullptr)
		delete HackModule::save;

	HackModule::save = new BYTE[5];
	memcpy(HackModule::save, HackModule::opengl32_glbegin_proc_handle, 5);

	modify_mem(HackModule::opengl32_glbegin_proc_handle, HackModule::hack_glbegin_proc_handle);

	goto trueRet;

trueRet:
	return TRUE;

falseRet:
	return FALSE;

}


void 
modify_mem(PVOID src, PVOID dst)
{
	UINT tmp2 = (UINT)dst, tmp1 = (UINT)src;
	UINT addr = 0;
	DWORD dwIdOld = 0;
	BYTE *sAddr = new unsigned char[5];

	VirtualProtectEx(HackModule::proc_handle, HackModule::opengl32_glbegin_proc_handle, 5, PAGE_READWRITE, &dwIdOld);
	sAddr[0] = 0xE9;
	addr = tmp2 - (tmp1 + 5);
	memcpy(sAddr + 1, &addr, 4);

	//将所属进程中glBegin的前5个字节改为JMP 到hack_glbegin_proc_handle 
	WriteProcessMemory(HackModule::proc_handle, HackModule::opengl32_glbegin_proc_handle, sAddr, 5, 0);
	VirtualProtectEx(HackModule::proc_handle, HackModule::opengl32_glbegin_proc_handle, 5, dwIdOld, &dwIdOld);

	delete[] sAddr;
}


void 
restore_mem(BYTE *src, PVOID dst, int size)
{
	DWORD dwIdOld = 0;
	VirtualProtectEx(HackModule::proc_handle, dst, size, PAGE_READWRITE, &dwIdOld);

	memcpy(dst, src, size);

	//将所属进程中glBegin的前5个字节改为JMP 到hack_glbegin_proc_handle 
	WriteProcessMemory(HackModule::proc_handle, dst, src, 5, 0);
	VirtualProtectEx(HackModule::proc_handle, dst, size, dwIdOld, &dwIdOld);
}


void __stdcall 
hack_glbegin_proc_handle(GLenum mode) 
{
	GLBEGIN glBegin = (GLBEGIN)HackModule::opengl32_glbegin_proc_handle;
	GLBEGIN glDisable = (GLBEGIN)HackModule::opengl32_gldisable_proc_handle;

	if (mode == GL_TRIANGLE_STRIP || mode == GL_TRIANGLE_FAN)
	{

		glDisable(GL_DEPTH_TEST);

	}

	HackModule::mtx.lock(); {

		restore_mem(HackModule::save, HackModule::opengl32_glbegin_proc_handle, 5);
		glBegin(mode);
		modify_mem(HackModule::opengl32_glbegin_proc_handle, HackModule::hack_glbegin_proc_handle);

	} HackModule::mtx.unlock();
}


void 
debug_byte(const BYTE *out, int mode, int size)
{
	int ccc;
	LPWSTR lp;
	int strSize = size * 4 + 1;
	char *print = new char[strSize];
	memset(print, 0, strSize);

	switch (mode)
	{

	case DEBUG_HEX:

		for (int i = 0; i < size; i++)
		{

			sprintf_s(print, strSize, "%s %x ", print, out[i]);

		}

		MessageBoxA(NULL, print, "debug", MB_OK);

		break;

	case DEBUG_DEC:

		sprintf_s(print, strSize, " %u ", (UINT)out);
		MessageBoxA(NULL, print, "debug", MB_OK);

		break;

	case LAST_ERR:

		ccc = GetLastError();
		lp = new wchar_t[128];
		wsprintf(lp, L"%S%d", out, ccc);
		MessageBox(NULL, lp, L"DEBUG", MB_OK);

		delete[] lp;

		break;

	case DEBUG_OUT:

		lp = new wchar_t[128];
		wsprintf(lp, L"%S", out);
		MessageBox(NULL, lp, L"DEBUG", MB_OK);

		delete[] lp;

		break;

	default:
		1;

	}

	delete[] print;
}
