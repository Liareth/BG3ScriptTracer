#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <GameDefinitions/Osiris.h>

struct OsirisData
{
	HMODULE handle;
	bg3se::OsirisStaticGlobals globals;
	bg3se::DivFunctions functions;
};

inline void* func_addr(HMODULE handle, const char* name) { return GetProcAddress(handle, name); }

namespace bg3se
{

inline uint8_t* resolve_real_function_address(uint8_t* Address)
{
	// Resolve function pointer through relocations
	for (uint8_t* ptr = Address; ptr < Address + 64; ptr++)
	{
		// Look for the instruction "cmp qword ptr [rip+xxxxxx], 0"
		if (ptr[0] == 0x48 && ptr[1] == 0x83 && ptr[2] == 0x3d && ptr[6] == 0x00 &&
			// Look for the instruction "jmp xxxx"
			ptr[13] == 0xe9)
		{
			int32_t relOffset = *reinterpret_cast<int32_t*>(ptr + 14);
			return ptr + relOffset + 18;
		}
	}

	// Could not find any relocations
	return Address;
}

inline bg3se::OsirisStaticGlobals load_globals(HMODULE osiris)
{
	FARPROC osirisCtor = GetProcAddress(osiris, "??0COsiris@@QEAA@XZ");
	if (!osirisCtor) {
		assert(false);
	}

	uint8_t* Addr = resolve_real_function_address((uint8_t*)osirisCtor);

	// Try to find pointers of Osiris globals
	const unsigned NumGlobals = 9;
	uint8_t* globals[NumGlobals];
	unsigned foundGlobals = 0;
	for (uint8_t* ptr = Addr; ptr < Addr + 0x500; ptr++)
	{
		// Look for the instruction "mov <reg>, r14"
		if ((ptr[0] == 0x49 || ptr[0] == 0x48) && ptr[1] == 0x8B &&
			// Look for the instruction "mov cs:[rip + xxx], <64-bit register>"
			ptr[3] == 0x48 && ptr[4] == 0x89 && (ptr[5] & 0xC7) == 0x05)
		{
			int32_t relOffset = *reinterpret_cast<int32_t*>(ptr + 6);
			uint64_t osiPtr = (uint64_t)ptr + relOffset + 10;
			globals[foundGlobals++] = (uint8_t*)osiPtr;
			if (foundGlobals == NumGlobals) break;
		}
	}

	if (foundGlobals < NumGlobals)
	{
		assert(false);
	}

	bg3se::OsirisStaticGlobals staticGlobals;
	staticGlobals.Variables = (bg3se::VariableDb**)globals[0];
	staticGlobals.Types = (bg3se::OsiTypeDb**)globals[1];
	staticGlobals.Enums = (bg3se::EnumDb**)globals[2];
	staticGlobals.Functions = (bg3se::FunctionDb**)globals[3];
	staticGlobals.Objects = (bg3se::ObjectDb**)globals[4];
	staticGlobals.Goals = (bg3se::GoalDb**)globals[5];
	staticGlobals.Adapters = (bg3se::AdapterDb**)globals[6];
	staticGlobals.Databases = (bg3se::DatabaseDb**)globals[7];
	staticGlobals.Nodes = (bg3se::NodeDb**)globals[8];
	return staticGlobals;
}

}
