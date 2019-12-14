#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <optional>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>

#include <conio.h>
#include <Windows.h>

#define SOL_CHECK_ARGUMENTS 1
#include "sol.hpp"
#include "capstone.h"
#include "platform.h"
#include "pe_bliss.h"

#include "capstone_api.hpp"
#include "lua_api.hpp"
#include "pe_api.hpp"

#if _DEBUG
#pragma comment(lib, "..\\Debug\\lua51_dll.lib")
#pragma comment(lib, "..\\Debug\\capstone_dll.lib")
#else
#pragma comment(lib, "..\\Release\\lua51_dll.lib")
#pragma comment(lib, "..\\Release\\capstone_dll.lib")
#endif

using namespace std;

namespace G
{
	extern sol::state Lua;
}