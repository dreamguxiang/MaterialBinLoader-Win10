#include <fcntl.h>
#include <io.h>
#include <tchar.h>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <Windows.h>

#include "Hook/Hook.h"
#include "Hook/MemoryUtils.h"
#include "Plugin.h"
#include <map>
using namespace std::filesystem;
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
	if (path.find("\\Packages\\microsoft.minecraftuwp_8wekyb3d8bbwe\\AC") != std::string::npos) {
		replaceAll(path, "\\Packages\\microsoft.minecraftuwp_8wekyb3d8bbwe\\AC", "");
		path += "\\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\";
	}
	else {
		replaceAll(path, "\\Packages\\microsoft.minecraftwindowsbeta_8wekyb3d8bbwe\\AC", "");
		path += "\\Packages\\Microsoft.MinecraftWindowsBeta_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\";
	}
	return path;
}

std::string UTF82String(std::u8string str) {
	return reinterpret_cast<std::string&>(str);
}

void ReadBin() {
	std::filesystem::directory_iterator ent(GetMCBEPath() + "renderer\\materials");
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
		return;
	}
	SetConsoleCP(CP_UTF8);
	FILE* fDummy;
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	std::cout.clear();
	std::clog.clear();
	std::cerr.clear();
	std::cin.clear();

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
		ReadBin();
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define FIND_ADDR(Ver,Sig)                            \
    {void* ptr = ll::memory::resolveSignature(Sig);    \
     if (ptr) { return ptr;  }}              


void* findAddr(std::string name) {	
	switch (do_hash(name.c_str()))
	{
	case do_hash("readFile"): {
		FIND_ADDR("1.19.40-1.19.81", "48 89 5C 24 ? 55 56 57 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 70 49 8B C0 ");
		FIND_ADDR("1.20.0.23", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 20 49 8B C0");
		////////////////////////error/////////////////////
		CreateConsole();
		std::cout << "XXX::readFile address not found!!!" << std::endl;
		break;
	}
	case do_hash("ResourcePackManager::ResourcePackManager"): {
		FIND_ADDR("", "48 89 ?? ?? ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 0F B6 F1 49 8B D8 4C 8B F2 48 8B F9 48 89 ?? ?? 48 89 ?? ?? 48 8D ?? ?? 48 89 ?? ?? 45 33 ED 4C 89 ?? ?? 48 8B ?? ?? 48 85 C9 74 ?? 48 8B 01 48 8D ?? ?? 48 8B 00 FF ?? ?? ?? ?? ??");
		////////////////////////error/////////////////////
		CreateConsole();
		std::cout << "ResourcePackManager::ResourcePackManager address not found!!!" << std::endl;
	}
	default:
		break;
	}
	return nullptr;
}

ResourcePackManager* GlobalResourcePackManager = nullptr;

LL_AUTO_STATIC_HOOK(
	HOOK0,
	HookPriority::Normal,
	findAddr("ResourcePackManager::ResourcePackManager"),
	ResourcePackManager* , ResourcePackManager* a1, __int64 a2, void* a3, char a4
){
	if(GlobalResourcePackManager == nullptr && a4){
		GlobalResourcePackManager = a1;
	}
	return origin(a1, a2, a3, a4);
}

LL_AUTO_STATIC_HOOK(
	Hook1,
	HookPriority::Normal,
	findAddr("readFile"),
	std::string*, void* _this, std::string* a2, Core::Path* a3
) {
	auto& data = a3->mPath.mUtf8StdString;
	if (data.size() < 32) {
		return origin(_this, a2, a3);
	}

	if (data.find("data/renderer/materials/") != std::string::npos && strncmp(data.c_str() + data.size() - 13, ".material.bin", 13) == 0) {
		std::string str = data.substr(data.find_last_of('/') + 1);
		std::string* resourceStream = new std::string();
		auto result = GlobalResourcePackManager->load(*new ResourceLocation("renderer/materials/"+str), *resourceStream);
		if (!result) {
			//std::cout << "Failure location=" << str << std::endl;
			auto it = BinList.find(str);
			if (it != BinList.end()) {
				std::string path = it->second;
				a3->mPath.mUtf8StdString = path;
			}
		}
		else {
			//std::cout << "Success location=" << str <<" len:"<< resourceStream->length() << std::endl;
			origin(_this, a2, a3);
			a2->clear();
			*a2 = *resourceStream;
			return a2;
		}
	}
	return origin(_this, a2, a3);
}