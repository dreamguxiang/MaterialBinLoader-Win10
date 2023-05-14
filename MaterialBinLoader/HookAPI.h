#pragma once

#include <Hash.h>
#include <string>
#include <Windows.h>
#include <Psapi.h>
#include "Memory.h"

#define INRANGE(x,a,b)   (x >= a && x <= b)
#define GET_BYTE( x )    (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))

#include <detours/detours.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <thread>
#include <sstream>
namespace Utils {
    static LPCSTR hModuleName;
    static bool running;
}

namespace {
    namespace PtrConv {
        inline std::string ptrToStr(uintptr_t ptr) {
            std::ostringstream ss;
            return ss.str();
        }
        inline void* uintptrToPtr(uintptr_t ptr) {
            return (void*)ptr;
        }
        template <typename dst_type = void*, typename src_type = int>
        inline void* toRawPtr(int src) {
            return (void*)static_cast<__int64>(src);
        }
        template <typename dst_type = void*, typename src_type = __int64>
        inline void* toRawPtr(__int64 src) {
            return (void*)src;
        }
        template <typename dst_type, typename src_type>
        inline dst_type toRawPtr(src_type src) {
            static_assert(std::is_pointer<src_type>() || std::is_member_pointer<src_type>(), "HookAPI PtrConv::toRawPtr:src_type should be a pointer");
            return *static_cast<dst_type*>(static_cast<void*>(&src));
        }
    } // namespace PtrConv
}

inline static void HookFunction__begin() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
}
inline static long HookFunction__finalize() {
    return DetourTransactionCommit();
}
static inline int realHook(void* oldfunc, void** poutold, void* newfunc) {
    void* target = oldfunc;
    HookFunction__begin();
    int rv = DetourAttach(&target, newfunc);
    HookFunction__finalize();
    *poutold = target;
    return rv;
}

inline int HookFunction(void* oldfunc, void** poutold, void* newfunc) {
    static std::unordered_map<void*, void**> ptr_pori;
    auto it = ptr_pori.find(oldfunc);
    if (it == ptr_pori.end()) {
        int rv = realHook(oldfunc, poutold, newfunc);
        if (rv != 0)
            return rv;
        ptr_pori[oldfunc] = poutold;
        return 0;
    }
    else {
        *poutold = *it->second;
        *it->second = newfunc;
        return 0;
    }
}

template <typename RTN = void, typename... Args>
RTN inline VirtualCall(void const* _this, uintptr_t off, Args... args) {
    return (*(RTN(**)(void const*, Args...))(*(uintptr_t*)_this + off))(_this, args...);
}

template <typename T, int off>
inline T& dAccess(void* ptr) {
    return *(T*)(((uintptr_t)ptr) + off);
}
template <typename T, int off>
inline T const& dAccess(void const* ptr) {
    return *(T*)(((uintptr_t)ptr) + off);
}
template <typename T>
inline T& dAccess(void* ptr, uintptr_t off) {
    return *(T*)(((uintptr_t)ptr) + off);
}
template <typename T>
inline const T& dAccess(void const* ptr, uintptr_t off) {
    return *(T*)(((uintptr_t)ptr) + off);
}
inline uintptr_t FindSig(const char* szSignature) {
    const char* pattern = szSignature;
    uintptr_t firstMatch = 0;
    static const uintptr_t rangeStart = (uintptr_t)GetModuleHandleA(Utils::hModuleName);
    static MODULEINFO miModInfo;
    static bool init = false;
    if (!init) {
        init = true;
        GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
    }
    static const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;
    BYTE patByte = GET_BYTE(pattern);
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

template <size_t N>
struct FixedString {
    char buf[N + 1]{};
    constexpr FixedString(char const* s) {
        for (unsigned i = 0; i != N; ++i)
            buf[i] = s[i];
    }
    constexpr operator char const* () const {
        return buf;
    }
};
template <size_t N>
FixedString(char const (&)[N])->FixedString<N - 1>;

template <FixedString Fn>
__declspec(selectany) void* __dlsym_ptr_cache = dlsym_real(Fn);

#define VA_EXPAND(...) __VA_ARGS__
template <FixedString Fn, typename ret, typename... p>
static inline auto __imp_Call() {
    return ((ret(*)(p...))((void*)FindSig(Fn)));
}

template <void* Fn, typename ret, typename... p>
static inline auto __imp_Call2() {
    return ((ret(*)(p...))(Fn));
}

template <FixedString Sig>
__declspec(selectany) void* __sigfind_ptr_cache = (void*)FindSig(Sig);

template <FixedString Sig, typename ret, typename... p>
static __forceinline auto __imp_Call_Sig() {
    return ((ret(*)(p...))(__sigfind_ptr_cache<Sig>));
}

template <typename ret, typename... p>
static __forceinline auto __imp_Call_Addr(void* Fn) {
    return ((ret(*)(p...))(Fn));
}

#define AddrCall(fn, ret, ...) (__imp_Call_Addr<ret, __VA_ARGS__>((void*)fn))
#define SigCall(fn, ret, ...) (__imp_Call_Sig<fn, ret, __VA_ARGS__>())


class THookRegister {
public:
    THookRegister(void* address, void* hook, void** org) {
        auto ret = HookFunction(address, org, hook);
        if (ret != 0) {
            printf("FailedToHook: %p\n", address);
        }
    }

    template <typename T>
    THookRegister(const char* sym, T hook, void** org) {
        union {
            T a;
            void* b;
        } hookUnion;
        hookUnion.a = hook;
        THookRegister(sym, hookUnion.b, org);
    }
    template <typename T>
    THookRegister(void* address, T hook, void** org) {
        union {
            T a;
            void* b;
        } hookUnion;
        hookUnion.a = hook;
        THookRegister(address, hookUnion.b, org);
    }
};

#define VA_EXPAND(...) __VA_ARGS__
template <CHash, CHash>
struct THookTemplate;
template <CHash, CHash>
extern THookRegister THookRegisterTemplate;

#define _TInstanceHook(class_inh, pclass, iname, sym, ret, ...)                              \
    template <>                                                                              \
    struct THookTemplate<do_hash(iname), do_hash2(iname)> class_inh {                        \
        typedef ret (THookTemplate::*original_type)(__VA_ARGS__);                            \
        static original_type& _original() {                                                  \
            static original_type storage;                                                    \
            return storage;                                                                  \
        }                                                                                    \
        template <typename... Params>                                                        \
        static ret original(pclass* _this, Params&&... params) {                             \
            return (((THookTemplate*)_this)->*_original())(std::forward<Params>(params)...); \
        }                                                                                    \
        ret _hook(__VA_ARGS__);                                                              \
    };                                                                                       \
    template <>                                                                              \
    static THookRegister THookRegisterTemplate<do_hash(iname), do_hash2(iname)>{             \
        sym, &THookTemplate<do_hash(iname), do_hash2(iname)>::_hook,                         \
        (void**)&THookTemplate<do_hash(iname), do_hash2(iname)>::_original()};               \
    ret THookTemplate<do_hash(iname), do_hash2(iname)>::_hook(__VA_ARGS__)

#define _TInstanceDefHook(iname, sym, ret, type, ...) \
    _TInstanceHook(                                   \
        : public type, type, iname, sym, ret, VA_EXPAND(__VA_ARGS__))
#define _TInstanceNoDefHook(iname, sym, ret, ...) \
    _TInstanceHook(, void, iname, sym, ret, VA_EXPAND(__VA_ARGS__))

#define _TStaticHook(pclass, iname, sym, ret, ...)                               \
    template <>                                                                  \
    struct THookTemplate<do_hash(iname), do_hash2(iname)> pclass {               \
        typedef ret (*original_type)(__VA_ARGS__);                               \
        static original_type& _original() {                                      \
            static original_type storage;                                        \
            return storage;                                                      \
        }                                                                        \
        template <typename... Params>                                            \
        static ret original(Params&&... params) {                                \
            return _original()(std::forward<Params>(params)...);                 \
        }                                                                        \
        static ret _hook(__VA_ARGS__);                                           \
    };                                                                           \
    template <>                                                                  \
    static THookRegister THookRegisterTemplate<do_hash(iname), do_hash2(iname)>{ \
        sym, &THookTemplate<do_hash(iname), do_hash2(iname)>::_hook,             \
        (void**)&THookTemplate<do_hash(iname), do_hash2(iname)>::_original()};   \
    ret THookTemplate<do_hash(iname), do_hash2(iname)>::_hook(__VA_ARGS__)

#define _TStaticDefHook(iname, sym, ret, type, ...) \
    _TStaticHook(                                   \
        : public type, iname, sym, ret, VA_EXPAND(__VA_ARGS__))
#define _TStaticNoDefHook(iname, sym, ret, ...) \
    _TStaticHook(, iname, sym, ret, VA_EXPAND(__VA_ARGS__))

#define SHook2(iname, ret, sig, ...) _TStaticNoDefHook(iname, (void*)FindSig(sig), ret, VA_EXPAND(__VA_ARGS__))
#define SHook(ret, sig, ...) SHook2(sig, ret, sig, VA_EXPAND(__VA_ARGS__))
#define SStaticHook2(iname, ret, sig, type, ...) \
    _TStaticDefHook(iname, (void*)FindSig(sig), ret, type, VA_EXPAND(__VA_ARGS__))
#define SStaticHook(ret, sig, type, ...) SStaticHook2(sig, ret, sig, type, VA_EXPAND(__VA_ARGS__))
#define SClasslessInstanceHook2(iname, ret, sig, ...) \
    _TInstanceNoDefHook(iname, (void*)FindSig(sig), ret, VA_EXPAND(__VA_ARGS__))
#define SClasslessInstanceHook(ret, sig, ...) \
    SClasslessInstanceHook2(sig, ret, sig, VA_EXPAND(__VA_ARGS__))
#define SInstanceHook2(iname, ret, sig, type, ...) \
    _TInstanceDefHook(iname, (void*)FindSig(sig), ret, type, VA_EXPAND(__VA_ARGS__))
#define SInstanceHook(ret, sig, type, ...) \
    SInstanceHook2(sig, ret, sig, type, VA_EXPAND(__VA_ARGS__))

#define AHook2(iname, ret, addr, ...) _TStaticNoDefHook(iname, PtrConv::toRawPtr<void*>(addr), ret, VA_EXPAND(__VA_ARGS__))
#define AHook(ret, addr, ...) AHook2(#addr, ret, addr, VA_EXPAND(__VA_ARGS__))
#define AStaticHook2(iname, ret, addr, type, ...) \
    _TStaticDefHook(iname, PtrConv::toRawPtr<void*>(addr), ret, type, VA_EXPAND(__VA_ARGS__))
#define AStaticHook(ret, addr, type, ...) AStaticHook2(#addr, ret, addr, type, VA_EXPAND(__VA_ARGS__))
#define AClasslessInstanceHook2(iname, ret, addr, ...) \
    _TInstanceNoDefHook(iname, PtrConv::toRawPtr<void*>(addr), ret, VA_EXPAND(__VA_ARGS__))
#define AClasslessInstanceHook(ret, addr, ...) \
    AClasslessInstanceHook2(#addr, ret, addr, VA_EXPAND(__VA_ARGS__))
#define AInstanceHook2(iname, ret, addr, type, ...) \
    _TInstanceDefHook(iname, PtrConv::toRawPtr<void*>(addr), ret, type, VA_EXPAND(__VA_ARGS__))
#define AInstanceHook(ret, addr, type, ...) \
    AInstanceHook2(#addr, ret, addr, type, VA_EXPAND(__VA_ARGS__))