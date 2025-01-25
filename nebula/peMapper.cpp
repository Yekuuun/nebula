#include "global.hpp"
#include "peLib.hpp"

/**
 * Manually load PE file & run it.
 */
static BOOL ManualMap(IN PBYTE pRawPe, IN SIZE_T sRawSize){
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

    std::cout << "\n\n[*] Successfully mapped PE into memory." << std::endl;
    std::cout << "[$] Press <ENTER> to end program" << std::endl;
    getchar();

    VirtualFree(pBuff, pNtHdr->OptionalHeader.SizeOfImage, MEM_RELEASE);
    return TRUE;
}

//entry point.
int main(int argc, char *argv[]){
    if(argc != 2){
        std::cout << "[!] Must pass one argument => <path_to_pe_file>" << std::endl;
        return EXIT_FAILURE;
    }

    //local.
    LPSTR lpPath = argv[1];
    BYTE* pRawPe = nullptr;
    DWORD dwSize = 0;

    pRawPe = ReadPeFile(lpPath, &dwSize);
    if(pRawPe == nullptr)
        return EXIT_FAILURE;
    
    if(!ManualMap(pRawPe, (SIZE_T)dwSize))
        return EXIT_FAILURE;

    HeapFree(GetProcessHeap(), 0, pRawPe);
    return EXIT_SUCCESS;
}