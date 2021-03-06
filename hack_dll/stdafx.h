#ifndef STDAFX_H
#define STDAFX_H

#define DEBUG_HEX 1
#define DEBUG_DEC 2
#define LAST_ERR  3
#define DEBUG_OUT 4

#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <tchar.h>
#include <mutex>

#define GL_TRIANGLE_STRIP    0x0005
#define GL_TRIANGLE_FAN      0x0006
#define GL_DEPTH_TEST        2929
//禁止编译不需要的windows接口，减小体积
#define WIN32_LEAN_AND_MEAN


typedef unsigned int GLenum;
typedef void (__stdcall * GLBEGIN)(GLenum mode);

//导出
extern "C"
{

	__declspec(dllexport) void __stdcall myGlBegin(GLenum mode);

}

#endif
