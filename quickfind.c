#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <minidumpapiset.h>

int Error(const char* msg) {
    printf("Error:%s Errorcode:%d", msg, GetLastError());
    return 1;
};

void create_dump(DWORD pid, char* process_name) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 1, pid);
    char str_pid[256];
    sprintf_s(str_pid, 256, "%d.dmp", pid);

    if (hProc == NULL) {
        Error("Could not get a handle to process\n");
    };

    HANDLE hFile = CreateFileA(
        str_pid,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        Error("Unable to create file");
    };

    BOOL write_result = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

    if (write_result == FALSE) {
        Error("Error unable to write memory dump to file");
    };

};

int is_binary(char* proc_name, char* argument, PPROCESSENTRY32 current_proc) {
    if (strstr(proc_name, argument) != NULL) {
        printf("\nExecutable found!\n");
        printf("Name:%s\nPID:%u\nPPID:%u\n", current_proc->szExeFile, current_proc->th32ProcessID, current_proc->th32ParentProcessID);
        create_dump(current_proc->th32ProcessID, current_proc->szExeFile);
        return 0;
    };
    return 1;

};

int main(int argc, char** argv) {

    if (argc < 2) {
        printf("Usage: %s <name of executable>\n", argv[0]);
        getchar();
        return 1;
    };

    PROCESSENTRY32 proc_entry;
    proc_entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Error("Couldn't take process snapshot");
    };

    if (!Process32First(hSnapshot, &proc_entry)) {
        Error("Couldn't get first process");
    };

    is_binary(proc_entry.szExeFile, argv[1], &proc_entry);

    do {
        is_binary(proc_entry.szExeFile, argv[1], &proc_entry);
    } while (Process32Next(hSnapshot, &proc_entry));

    printf("Finished\n");
    getchar();
    return 0;
};
