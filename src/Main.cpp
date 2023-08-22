#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define NOMINMAX
#include <windows.h>
#include <format>
#include <memory>
#include "Memory.hpp"
#include "Osiris.hpp"

OsirisData _osiris;

std::string format_arg(bg3se::OsiArgumentDesc& arg)
{
    enum class TypeExtended
    {
        None = 0,
        Integer = 1,
        Integer64 = 2,
        Real = 3,
        String = 4,
        GuidString = 5,

        // don't ask me wtff, I don't know ok??

        String6 = 6,
        String7 = 7,
        String11 = 11,
        String15 = 15,
        String16 = 16,
        String21 = 21,
        String32 = 32,
        String39 = 39,
    } type = (TypeExtended)arg.Value.TypeId;

    switch (type)
    {
    case TypeExtended::Integer:
        return std::format("{}", arg.Value.Int32);

    case TypeExtended::Integer64:
        return std::format("{}", arg.Value.Int64);

    case TypeExtended::Real:
        return std::format("{}", arg.Value.Float);

    case TypeExtended::String:
    case TypeExtended::GuidString:
    case TypeExtended::String6:
    case TypeExtended::String7:
    case TypeExtended::String11:
    case TypeExtended::String15:
    case TypeExtended::String16:
    case TypeExtended::String21:
    case TypeExtended::String32:
    case TypeExtended::String39:
        return arg.Value.String ? std::format("'{}'", arg.Value.String) : "nil";
    }

    return "UNKNOWN";
}

std::string format_in_args(bg3se::Function* func, bg3se::OsiArgumentDesc* args)
{
    int outCount = func->Signature->OutParamList.numOutParams();
    int inCount = func->Signature->Params->Params.Size - outCount;

    std::string formattedArgs;

    for (int i = 0; i < inCount; ++i)
    {
        formattedArgs += format_arg(*args);
        args = args->NextParam;
        if (i != inCount - 1) formattedArgs += ", ";
    }

    return formattedArgs;
}

std::string format_out_args(bg3se::Function* func, bg3se::OsiArgumentDesc* args)
{
    int outCount = func->Signature->OutParamList.numOutParams();
    int inCount = func->Signature->Params->Params.Size - outCount;
    for (int i = 0; i < inCount; ++i) { args = args->NextParam; }

    std::string formattedReturn;

    for (int i = 0; i < outCount; ++i)
    {
        formattedReturn += format_arg(*args);
        args = args->NextParam;
        if (i != outCount - 1) formattedReturn += ", ";
    }

    return formattedReturn;
}

namespace hooks
{
    std::unique_ptr<Hook> _osiris_call_hook;
    std::unique_ptr<Hook> _osiris_query_hook;
    std::unique_ptr<Hook> _osiris_event_hook;

    bool osiris_call_hook(uint32_t id, bg3se::OsiArgumentDesc* args)
    {
        bg3se::Function** func = (*_osiris.globals.Functions)->FindById(id);
        printf("%s(%s)\n", (*func)->Signature->Name, format_in_args(*func, args).c_str());
        return _osiris_call_hook->call_original<bool>(id, args);
    }

    bool osiris_query_hook(uint32_t id, bg3se::OsiArgumentDesc* args)
    {
        bg3se::Function** func = (*_osiris.globals.Functions)->FindById(id);
        bool ret = _osiris_query_hook->call_original<bool>(id, args);
        const std::string in_args = format_in_args(*func, args);
        const std::string out_args = format_out_args(*func, args);
        printf("%s(%s) -> %s\n", (*func)->Signature->Name, in_args.c_str(), out_args.c_str());
        return _osiris_query_hook->call_original<bool>(id, args);
    }

    int osiris_event_hook(void* _0, uint32_t id, bg3se::OsiArgumentDesc* args)
    {
        bg3se::Function** func = (*_osiris.globals.Functions)->FindById(id);
        printf("%s(%s)\n", (*func)->Signature->Name, format_in_args(*func, args).c_str());
        return _osiris_event_hook->call_original<bool>(_0, id, args);
    }
}

std::unique_ptr<Hook> _register_hook;

BOOL APIENTRY DllMain(HINSTANCE module, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
#ifndef NDEBUG
		//while (!IsDebuggerPresent()) { Sleep(100); }
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
#endif

		DisableThreadLibraryCalls(module);

		_osiris.handle = LoadLibrary("osiris.dll");

		_register_hook = std::make_unique<Hook>("_register_hook",
			func_addr(_osiris.handle, "?RegisterDIVFunctions@COsiris@@QEAAXPEAUTOsirisInitFunction@@@Z"),
			[](void* _this, bg3se::DivFunctions* functions) {
				// RegisterDIVFunctions is called multiple times - when starting the game, then when loading.
				if (static bool init = false; !init)
				{
					_osiris.functions = *functions;
					_osiris.globals = bg3se::load_globals(_osiris.handle);

					hooks::_osiris_call_hook = std::make_unique<Hook>("_osiris_call_hook", _osiris.functions.Call, &hooks::osiris_call_hook);
					hooks::_osiris_query_hook = std::make_unique<Hook>("_osiris_query_hook", _osiris.functions.Query, &hooks::osiris_query_hook);
					hooks::_osiris_event_hook = std::make_unique<Hook>("_osiris_event_hook", func_addr(_osiris.handle, "?Event@COsiris@@QEAA?AW4ReturnCode@osi@@IPEAVCOsiArgumentDesc@@@Z"), &hooks::osiris_event_hook);

					init = true;
				}

				_register_hook->call_original<void>(_this, functions);
			});
	}

	return TRUE;
}
