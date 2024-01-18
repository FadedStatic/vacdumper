#include <Windows.h>
#include <iostream>
#include <thread>
#include <string>
#include "patternscanner/scanner.hpp"
#include <fstream>
#include <algorithm>

#include "minhook/MinHook.h"

using vaclive_stub = char(__stdcall*)(DWORD* src, char flag);
vaclive_stub vaclive_old;

char __stdcall vaclive_sub_hook(DWORD* src, char flag) {
    if (reinterpret_cast<void*>(src[6]) != nullptr && src[5] > 8192) {
        OutputDebugStringA(std::vformat("VACDUMPER: Trying to fetch new module... {:d}\n", std::make_format_args((int)src[5])).c_str());
        const auto* module_start = reinterpret_cast<std::uint8_t*>(src[6]);
        OutputDebugStringA("VACDUMPER: Where thi hoe brakin.");
        const auto mod_sz = static_cast<std::uintptr_t>(src[5]);
        OutputDebugStringA("VACDUMPER: Where thi hoe brakin 1.");
        const auto module_dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER*>(module_start);
        OutputDebugStringA("VACDUMPER: Where thi hoe brakin 2.");
        const auto module_nt_headers = *reinterpret_cast<const IMAGE_NT_HEADERS*>(module_start + module_dos_header.e_lfanew);
        OutputDebugStringA(std::vformat("VACDUMPER: Module {:d} was loaded, dumping...\n", std::make_format_args(module_nt_headers.OptionalHeader.SizeOfCode)).c_str());
        CreateDirectoryA("C:\\vac_modules", nullptr);

        std::ofstream file("C:\\vac_modules\\vac_module_" + std::to_string(module_nt_headers.OptionalHeader.SizeOfCode) + ".dll", std::ios::out | std::ios::binary);
        file.write(reinterpret_cast<char*>(src[6]), mod_sz);
        file.close();
        OutputDebugStringA(std::vformat("VACDUMPER: Saved module {:d} to {:s}\r\n", std::make_format_args(module_nt_headers.OptionalHeader.SizeOfCode, "C:\\vac_modules\\vac_module_" + std::to_string(module_nt_headers.OptionalHeader.SizeOfCode) + ".dll")).c_str());
    }

    return vaclive_old(src, flag);
}

int main() {
    auto curr_proc = process();

    const auto phmodstr_xrefs = scanner::string_scan(curr_proc, "pModule->m_pModule == NULL");
    if (phmodstr_xrefs.empty()) {
        OutputDebugStringA("VACDUMPER: Error, Could not find xrefs to phmod str\n");
        return 0;
    }

    const auto vaclive_stub = util::get_prologue(curr_proc, phmodstr_xrefs[0].loc);
    if (!vaclive_stub.has_value()) {
        OutputDebugStringA("VACDUMPER: Error, Could not find vac live stub\n");
        return 0;
    }

    OutputDebugStringA(std::vformat("VACDUMPER: VAC stub found at: 0x{:02X} (0x{:02X})\r\n", std::make_format_args(*vaclive_stub, *vaclive_stub - reinterpret_cast<uintptr_t>(GetModuleHandleA("steamservice.dll")))).c_str());

    MH_Initialize();
    MH_CreateHook(reinterpret_cast<LPVOID>(*vaclive_stub), &vaclive_sub_hook, reinterpret_cast<PVOID*>(&vaclive_old));
    MH_EnableHook(reinterpret_cast<LPVOID>(*vaclive_stub));

    OutputDebugStringA("VACDUMPER: Hook initialized.\n");

    return 0;
}

int __stdcall DllMain(const HINSTANCE dll_handle, const DWORD call_reason, const void** reserved) {
    if (call_reason == DLL_PROCESS_ATTACH)
        std::thread(main).detach();

    return 0;
}