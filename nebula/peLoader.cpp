#include "global.hpp"
#include "peLib.hpp"

/**
 * Manually load PE file & run it.
 */
static BOOL ManualLoader(IN PBYTE pRawPe, IN SIZE_T sRawSize){
    PBYTE pBuff = NULL;

    PIMAGE_DOS_HEADER pDos   = (PIMAGE_DOS_HEADER)pRawPe;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)pRawPe + pDos->e_lfanew);

    if(pNtHdr == NULL){
        return FALSE;
    }

    pBuff = (PBYTE)VirtualAlloc(NULL, pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(pBuff == NULL){
        printf("[!] Error allocating memory using VirtualAlloc with error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[*] Memory allocated at 0x%p \n", pBuff);
    MapSections(pRawPe, pBuff, pNtHdr);

    if(!Relocate(pBuff, pNtHdr, (FIELD_PTR)pBuff)){
        printf("[!] Error applying relocations. \n");
        VirtualFree(pBuff, pNtHdr->OptionalHeader.SizeOfImage, MEM_RELEASE);
        return FALSE;
    }

    printf("[*] Successfully applied relocations. \n");

    if(!LoadImports(pBuff, pNtHdr)){
        printf("[!] Error loading imports. \n");
        VirtualFree(pBuff, pNtHdr->OptionalHeader.SizeOfImage, MEM_RELEASE);
        return FALSE;
    }

    ULONG_PTR pEntryPoint = pNtHdr->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)pBuff;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pEntryPoint, NULL, 0, NULL);
    if(hThread){
        printf("[*] New thread running at : 0x%p \n", pEntryPoint);
        WaitForSingleObject(hThread, INFINITE);
    }
    else {
        printf("[!] Error creating new thread. \n");
        VirtualFree(pBuff, pNtHdr->OptionalHeader.SizeOfImage, MEM_RELEASE);
        return FALSE;
    }

    return TRUE;
}

//entry point.
int main(int argc, char *argv[]){
    if(argc < 2){
        printf("[!] Must pass one argument : <path_to_file>\n");
        return EXIT_FAILURE;
    }

    LPSTR lpPath = argv[1];
    DWORD dwSize = 0;
    PBYTE pRawPe = NULL;

    pRawPe = ReadPeFile(lpPath, &dwSize);
    if(pRawPe == NULL){
        printf("[!] Error reading file. \n");
        return EXIT_FAILURE;
    }

    if(!IsValidPeFile(pRawPe)){
        printf("[!] Not a PE file.\n");
        HeapFree(GetProcessHeap(), 0, pRawPe);
        return EXIT_FAILURE;
    }

    printf("[*] Read %d bytes for file at base address : 0x%p \n", dwSize, pRawPe);

    if(!ManualLoader(pRawPe, (SIZE_T)dwSize)){
        HeapFree(GetProcessHeap(), 0, pRawPe);
        return EXIT_FAILURE;
    }

    printf("[#] Press <ENTER> to end aang & clean ressources.\n");
    getchar();

    printf("[$] Cleaning memory.\n[*] CIAO....\n");
    HeapFree(GetProcessHeap(), 0, pRawPe);
    return EXIT_SUCCESS;
}