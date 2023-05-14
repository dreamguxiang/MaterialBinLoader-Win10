#include "HookAPI.h"
#include <iostream>

namespace Core {

	class PathPart {
	public:
		std::string mUtf8StdString;
	};

	class Path {
	public:
		PathPart mPath;
		Path(std::string a1) {
			mPath.mUtf8StdString = a1;
		}

	};

	template <typename T>
	class PathBuffer {
		T value;
	public:
		T& get() {
			return value;
		}
		operator T& () noexcept { return value; }
		operator T const& () const noexcept { return value; }
	};

};

#include <Windows.h>
#include "HookAPI.h"
#include <fcntl.h>
#include <io.h>
#include <tchar.h>
#include <unordered_set>
#include <filesystem>
#include <fstream>
using namespace std::filesystem;
namespace fs = std::filesystem;
std::unordered_map<std::string, std::string> BinList;

std::string GetLocalAppDataPath() {
	char* pValue;
	size_t len;
	errno_t err = _dupenv_s(&pValue, &len, "LOCALAPPDATA");
	if (err) {
		return "";
	}
	std::string path = pValue;
	free(pValue);

	return path;
}

std::string& replaceAll(std::string& str, const std::string& old_value, const std::string& new_value) {
	while (true) {
		std::string::size_type pos(0);
		if ((pos = str.find(old_value)) != std::string::npos)
			str.replace(pos, old_value.length(), new_value);
		else break;
	}
	return str;
}

std::string GetMCBEPath() {
	std::string path = GetLocalAppDataPath();
	replaceAll(path, "\\Packages\\microsoft.minecraftuwp_8wekyb3d8bbwe\\AC", "");
	path += "\\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\";
	return path;
}

std::string UTF82String(std::u8string str) {
	return reinterpret_cast<std::string&>(str);
}

void ReadBin() {
	std::filesystem::directory_iterator ent(GetMCBEPath()+"renderer\\materials");
	for (auto& file : ent) {
		if (!file.is_regular_file())
			continue;
		auto& path = file.path();
		auto fileName = UTF82String(path.filename().u8string());

		std::string ext = UTF82String(path.extension().u8string());
		std::string parentPath = UTF82String(path.parent_path().u8string());
		std::string paths = parentPath + "\\" + fileName;
		BinList[fileName] = paths;
	}
}
void CreateConsole()
{
	if (!AllocConsole()) {
		// Add some error handling here.
		// You can call GetLastError() to get more info about the error.
		return;
	}
	SetConsoleCP(CP_UTF8);
	// std::cout, std::clog, std::cerr, std::cin
	FILE* fDummy;
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	std::cout.clear();
	std::clog.clear();
	std::cerr.clear();
	std::cin.clear();

	// std::wcout, std::wclog, std::wcerr, std::wcin
	HANDLE hConOut = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hConIn = CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
	SetStdHandle(STD_ERROR_HANDLE, hConOut);
	SetStdHandle(STD_INPUT_HANDLE, hConIn);
	std::wcout.clear();
	std::wclog.clear();
	std::wcerr.clear();
	std::wcin.clear();
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		//CreateConsole();
		ReadBin();
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

SHook2("AppPlatform::readAssetFile", std::string*, "48 89 ?? ?? ?? 55 56 57 41 56 41 57 48 8D ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? "
	"?? ?? ?? 48 33 C4 48 89 ?? ?? 49 8B C0 48 8B FA 48 89 ?? ?? 45 33 F6 44 89 ?? ?? ?? 0F 57 C9", void* _this, std::string* a2, Core::Path* a3) {
	auto& data = a3->mPath.mUtf8StdString;
	if (data.size() < 32) {
		return original(_this, a2, a3);
	}

    if (data.find("renderer/materials/") != std::string::npos && strncmp(data.c_str() + data.size() - 13, ".material.bin", 13) == 0) {
		std::string str = data.substr(data.find_last_of('/') + 1);
		auto it = BinList.find(str);
		if (it != BinList.end()) {
			std::string path = it->second;
			a3->mPath.mUtf8StdString = path;
		}

    }
	return original(_this, a2, a3);
}