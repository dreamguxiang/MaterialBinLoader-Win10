/* Defines */
#define WIN32_LEAN_AND_MEAN /* This removes all rarely used Windows.h Features to reduce size. */

/* Includes */
#include <Windows.h>
#include <iostream>
#include <AclAPI.h>
#include <string>
#include <sddl.h>
#include <TlHelp32.h>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <fstream>

DWORD SetDllPermissions(std::string wstrFilePath) { /* From UC(https://www.unknowncheats.me/forum/general-programming-and-reversing/177183-basic-intermediate-techniques-uwp-app-modding.html) */
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS eaAccess;
    SECURITY_INFORMATION siInfo = DACL_SECURITY_INFORMATION;
    DWORD dwResult = ERROR_SUCCESS;
    PSID pSID;

    // Get a pointer to the existing DACL
    dwResult = GetNamedSecurityInfoA(wstrFilePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
    if (dwResult != ERROR_SUCCESS)
        goto Cleanup;

    // Get the SID for ALL APPLICATION PACKAGES using its SID string
    ConvertStringSidToSidA("S-1-15-2-1", &pSID);
    if (pSID == NULL)
        goto Cleanup;

    ZeroMemory(&eaAccess, sizeof(EXPLICIT_ACCESS));
    eaAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
    eaAccess.grfAccessMode = SET_ACCESS;
    eaAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    eaAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    eaAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    eaAccess.Trustee.ptstrName = (LPSTR)pSID;

    // Create a new ACL that merges the new ACE into the existing DACL
    dwResult = SetEntriesInAclA(1, &eaAccess, pOldDACL, &pNewDACL);
    if (ERROR_SUCCESS != dwResult)
        goto Cleanup;

    // Attach the new ACL as the object's DACL
    dwResult = SetNamedSecurityInfoA((LPSTR)wstrFilePath.c_str(), SE_FILE_OBJECT, siInfo, NULL, NULL, pNewDACL, NULL);
    if (ERROR_SUCCESS != dwResult)
        goto Cleanup;

Cleanup:
    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);

    return dwResult;
}

DWORD GetMCBEPID(std::string exePath) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry)) {
            while (Process32Next(hSnap, &procEntry)) {
                if (!_stricmp(procEntry.szExeFile, exePath.c_str())) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            }
        }
    }

    CloseHandle(hSnap);
    return procId;
}
//GetLocalAppDataPath
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

std::string GetMCBEPath() {
	std::string path = GetLocalAppDataPath();
	path += "\\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\";
    return path;
}

void clearDir(std::string dir) {
	std::filesystem::directory_iterator ent(dir);
    for (auto& file : ent) {
		if (!file.is_regular_file())
			continue;
		auto& path = file.path();
		auto fileName = path.filename().u8string();
		std::string ext = path.extension().u8string();
		std::string parentPath = path.parent_path().u8string();
		std::string paths = parentPath + "\\" + fileName;
        		std::filesystem::remove(paths);
    }
}


void copy2MCPath() {
    clearDir(GetMCBEPath() + "renderer\\materials\\");
    std::filesystem::directory_iterator ent("./renderer/materials");
    for (auto& file : ent) {
        if (!file.is_regular_file())
            continue;
        auto& path = file.path();
        auto fileName = path.filename().u8string();

        std::string ext = path.extension().u8string();
        std::string parentPath = path.parent_path().u8string();
        std::string paths = parentPath + "\\" + fileName;

        std::filesystem::copy_file(paths, GetMCBEPath() + "renderer\\materials\\" + fileName, std::filesystem::copy_options::overwrite_existing);
    }
}


bool Inject(const char* dllPath, std::string exePath) {
    DWORD PID = GetMCBEPID(exePath);
    if (!PID)
        return false;
    HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!Proc)
        return false;
    char DllName[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, DllName, NULL);
    LPVOID LoadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!LoadLib)
        return false;
    LPVOID RemoteString = VirtualAllocEx(Proc, NULL, strlen(DllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!RemoteString)
        return false;
    WriteProcessMemory(Proc, RemoteString, DllName, strlen(DllName), NULL);
    CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLib, (LPVOID)RemoteString, NULL, NULL);

    CloseHandle(Proc);
    return true;
}

void createDir(std::string dir) {
    CreateDirectoryA(dir.c_str(), NULL);
}
int main(int argc,char *argv[]) {
    createDir("renderer");
    createDir("renderer/materials");
    createDir(GetMCBEPath() + "renderer");
    createDir(GetMCBEPath() + "renderer/materials");
    copy2MCPath();
    std::cout << "[1]Release  [2]Preview" << std::endl;
    int version;
    std::cin >> version;
    std::string exePath = "Minecraft.Windows.exe";
    if (version == 1) {
        system("explorer.exe shell:appsFolder\\Microsoft.MinecraftUWP_8wekyb3d8bbwe!App");
        exePath = "Minecraft.Windows.exe";
        system("cls");

    }
    else if (version == 2) {
        system("explorer.exe shell:appsFolder\\Microsoft.MinecraftWindowsBeta_8wekyb3d8bbwe!App");
        exePath = "Minecraft.WindowsBeta.exe";
        system("cls");
    }
    else {
        system("cls");
    }

    Sleep(200);

    DWORD dwResult = SetDllPermissions("MaterialBinLoader.dll");
    if (dwResult != ERROR_SUCCESS) {
        std::cout << "Failed to Set Dll Permissions.\n";
        std::cout << "Back to Start...\n";
        Sleep(800);
        system("cls");
    }

    if (Inject("MaterialBinLoader.dll", exePath))
        std::cout << "MaterialBinLoader.dll Injected.\n";
    else
        std::cout << "Failed to Inject.\n";


    Sleep(5000);
    system("cls");
}
