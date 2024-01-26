#include <fstream>
#include <string>

#include "patternscanner/scanner.hpp"
#include "minhook/MinHook.h"

using vaclm_stub = char(__stdcall*)(DWORD* src, char flag);
vaclm_stub vaclm_old;
int vac_counter = 15;

char __stdcall vaclm_stub_hook(DWORD* src, char flag) {
    if (reinterpret_cast<void*>(src[6]) != nullptr) {
        OutputDebugStringA(std::vformat("VACDUMPER: Module {:d} was loaded, dumping...\n", std::make_format_args(vac_counter)).c_str());
        CreateDirectoryA("C:\\vac_modules", nullptr);

        std::ofstream file("C:\\vac_modules\\vac_module_" + std::to_string(vac_counter) + ".dll", std::ios::out | std::ios::binary);
        file.write(reinterpret_cast<char*>(src[6]), src[5]);
        file.close();
        OutputDebugStringA(std::vformat("VACDUMPER: Saved module {:d} to {:s}\r\n", std::make_format_args(vac_counter, "C:\\vac_modules\\vac_module_" + std::to_string(vac_counter) + ".dll")).c_str());
        vac_counter++;
    }

    return vaclm_old(src, flag);
}

int main() {
    auto curr_proc = process();

    const auto phmodstr_xrefs = scanner::string_scan(curr_proc, "pModule->m_pModule == NULL");
    if (phmodstr_xrefs.empty()) {
        OutputDebugStringA("VACDUMPER: Error, Could not find xrefs to phmod str\n");
        return 0;
    }

    const auto vaclm_stub = util::get_prologue(curr_proc, phmodstr_xrefs[0].loc);
    if (!vaclm_stub) {
        OutputDebugStringA("VACDUMPER: Error, Could not find vac load module stub\n");
        return 0;
    }

    OutputDebugStringA(std::vformat("VACDUMPER: VAC stub found at: 0x{:02X} (0x{:02X})\r\n", std::make_format_args(*vaclm_stub, *vaclm_stub - reinterpret_cast<uintptr_t>(GetModuleHandleA("steamservice.dll")))).c_str());


    jmp_found:
    MH_Initialize();
    MH_CreateHook(reinterpret_cast<LPVOID>(*vaclm_stub), &vaclm_stub_hook, reinterpret_cast<PVOID*>(&vaclm_old));
    MH_EnableHook(reinterpret_cast<LPVOID>(*vaclm_stub));
    OutputDebugStringA("VACDUMPER: Hook initialized.\n");

    return 0;
}

int __stdcall DllMain(const HINSTANCE dll_handle, const DWORD call_reason, const void** reserved) {
    if (call_reason == DLL_PROCESS_ATTACH)
        std::thread(main).detach();

    return 0;
}