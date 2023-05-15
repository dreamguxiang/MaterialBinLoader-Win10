
#include <iostream>
#include <Windows.h>
#include "detours/detours.h"
#include "Hook.h"
#include "MemoryUtils.h"
#include <Psapi.h>
#include <unordered_map>
#include <mutex>

namespace pl::hook {

    struct HookElement {
        FuncPtr  detour{};
        FuncPtr* originalFunc{};
        int      priority{};
        int      id{};

        bool operator<(const HookElement& other) const {
            if (priority != other.priority)
                return priority < other.priority;
            return id < other.id;
        }
    };

    struct HookData {
        FuncPtr               target{};
        FuncPtr               origin{};
        FuncPtr               start{};
        FuncPtr               thunk{};
        int                   hookId{};
        std::set<HookElement> hooks{};

        inline ~HookData() {
            if (this->thunk != nullptr) {
                VirtualFree(this->thunk, 0, MEM_RELEASE);
                this->thunk = nullptr;
            }
        }

        inline void updateCallList() {
            FuncPtr* last = nullptr;
            for (auto& item : this->hooks) {
                if (last == nullptr) {
                    this->start = item.detour;
                    last = item.originalFunc;
                }
                else {
                    *last = item.detour;
                    last = item.originalFunc;
                }
            }
            if (last == nullptr)
                this->start = this->origin;
            else
                *last = this->origin;
        }

        inline int incrementHookId() {
            return ++hookId;
        }
    };

    std::unordered_map<FuncPtr, std::shared_ptr<HookData>> hooks{};

    std::mutex hooksMutex{};

    FuncPtr createThunk(FuncPtr* target) {
        constexpr auto THUNK_SIZE = 18;
        unsigned char  thunkData[THUNK_SIZE] = { 0 };
        // generate a thunk:
        // mov rax hooker1
        thunkData[0] = 0x48;
        thunkData[1] = 0xB8;
        memcpy(thunkData + 2, &target, sizeof(FuncPtr*));
        // mov rax [rax]
        thunkData[10] = 0x48;
        thunkData[11] = 0x8B;
        thunkData[12] = 0x00;
        // jmp rax
        thunkData[13] = 0xFF;
        thunkData[14] = 0xE0;

        auto thunk = VirtualAlloc(nullptr, THUNK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(thunk, thunkData, THUNK_SIZE);
        DWORD dummy;
        VirtualProtect(thunk, THUNK_SIZE, PAGE_EXECUTE_READ, &dummy);
        return thunk;
    }

    int processHook(FuncPtr target, FuncPtr detour, FuncPtr* originalFunc) {
        FuncPtr tmp = target;
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        int rv = DetourAttach(&tmp, detour);
        DetourTransactionCommit();
        *originalFunc = tmp;
        return rv;
    }

    [[maybe_unused]] int pl_hook(FuncPtr target, FuncPtr detour, FuncPtr* originalFunc, Priority priority) {
        std::lock_guard lock(hooksMutex);
        auto            it = hooks.find(target);
        if (it != hooks.end()) {
            auto hookData = it->second;
            hookData->hooks.insert({ detour, originalFunc, priority, hookData->incrementHookId() });
            hookData->updateCallList();
            return ERROR_SUCCESS;
        }

        auto hookData = new HookData{ target, target, detour, nullptr, {}, {} };
        hookData->thunk = createThunk(&hookData->start);
        hookData->hooks.insert({ detour, originalFunc, priority, hookData->incrementHookId() });
        auto ret = processHook(target, hookData->thunk, &hookData->origin);
        if (ret) {
            delete hookData;
            return ret;
        }
        hookData->updateCallList();
        hooks.emplace(target, std::shared_ptr<HookData>(hookData));
        return ERROR_SUCCESS;
    }

    [[maybe_unused]] bool pl_unhook(FuncPtr target, FuncPtr detour) {
        std::lock_guard lock(hooksMutex);
        auto            hookDataIter = hooks.find(target);
        if (hookDataIter == hooks.end()) {
            return false;
        }
        auto& hookData = hookDataIter->second;
        for (auto it = hookData->hooks.begin(); it != hookData->hooks.end(); ++it) {
            if (it->detour != detour)
                continue;
            hookData->hooks.erase(it);
            hookData->updateCallList();
            return true;
        }
        return false;
    }

} // namespace pl::hook

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BYTE(x)       (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS(x)                                                                                                    \
    (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (IN_RANGE(x, '0', '9') ? x - '0' : 0))

inline DWORD_PTR GetProcessBaseAddress(DWORD processId) {
    DWORD_PTR baseAddress = 0;
    HANDLE    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    HMODULE* moduleArray;
    LPBYTE    moduleArrayBytes;
    DWORD     bytesRequired = 0;

    if (!processHandle)
        return baseAddress;

    if (!EnumProcessModules(processHandle, nullptr, 0, &bytesRequired) || !bytesRequired)
        goto Ret;

    moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);
    if (!moduleArrayBytes) {
        goto Ret;
    }

    moduleArray = (HMODULE*)moduleArrayBytes;
    if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired)) {
        baseAddress = (DWORD_PTR)moduleArray[0];
    }
    LocalFree(moduleArrayBytes);

Ret:
    CloseHandle(processHandle);
    return baseAddress;
}

inline std::vector<std::string> split(std::string str, const std::string& pattern) {
    std::string::size_type   pos;
    std::vector<std::string> result;
    str += pattern;
    size_t size = str.size();
    for (size_t i = 0; i < size; i++) {
        pos = str.find(pattern, i);
        if (pos < size) {
            std::string s = str.substr(i, pos - i);
            result.push_back(s);
            i = pos + pattern.size() - 1;
        }
    }
    return result;
}

uintptr_t FindSig(const char* szSignature) {
    const char* pattern = szSignature;
    uintptr_t              firstMatch = 0;
    DWORD                  processId = GetCurrentProcessId();
    static const uintptr_t rangeStart = GetProcessBaseAddress(processId);
    static MODULEINFO      miModInfo;
    static bool            init = false;

    if (!init) {
        init = true;
        GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
    }

    static const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;
    BYTE                   patByte = GET_BYTE(pattern);
    const char* oldPat = pattern;

    for (uintptr_t pCur = rangeStart; pCur < rangeEnd; pCur++) {
        if (!*pattern)
            return firstMatch;

        while (*(PBYTE)pattern == ' ')
            pattern++;

        if (!*pattern)
            return firstMatch;

        if (oldPat != pattern) {
            oldPat = pattern;
            if (*(PBYTE)pattern != '\?')
                patByte = GET_BYTE(pattern);
        }
        if (*(PBYTE)pattern == '\?' || *(BYTE*)pCur == patByte) {
            if (!firstMatch)
                firstMatch = pCur;

            if (!pattern[2] || !pattern[1])
                return firstMatch;
            pattern += 2;
        }
        else {
            pattern = szSignature;
            firstMatch = 0;
        }
    }
    return 0;
}



namespace ll::memory {

	int hook(FuncPtr target, FuncPtr detour, FuncPtr* originalFunc, HookPriority priority) {
		return pl::hook::pl_hook(target, detour, originalFunc, static_cast<pl::hook::Priority>(priority));
	}

	bool unhook(FuncPtr target, FuncPtr detour) { return pl::hook::pl_unhook(target, detour); }

	FuncPtr resolveIdentifier(const char* identifier) {
		//auto p = resolveSymbol(identifier);
		return resolveSignature(identifier);
	}

    FuncPtr resolveIdentifier(void* identifier) {
        //auto p = resolveSymbol(identifier);
        return identifier;
    }

    //FuncPtr resolveSymbol(const char* symbol) { return pl::symbol_provider::pl_resolve_symbol(symbol); }

    FuncPtr resolveSignature(const char* signature) { return reinterpret_cast<FuncPtr>(FindSig(signature)); }

} // namespace ll::memory
