/**
 * Update permissions for a section.
 */

#include "global.hpp"
#include "peLib.hpp"

/**
 * Updating perms for a section.
 */
BOOL UpdatePerm(IN BYTE* pRawPe, IN DWORD dwSize, IN DWORD dwNewFlag, IN LPCSTR lpSectionName){
    SIZE_T lpSectionLen = strlen(lpSectionName);
    if(lpSectionLen > 8)
        return FALSE; //max len for a section name.
    
    PIMAGE_DOS_HEADER pDos   = (PIMAGE_DOS_HEADER)pRawPe;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)pRawPe + pDos->e_lfanew);

    //first section
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);
    for(WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++){
        BYTE* pSectionName = pSection[i].Name;
        if(memcmp(lpSectionName, pSectionName, lpSectionLen) == 0){
            std::cout << "[*] Section founded :" << lpSectionName << std::endl;
            printf("\t- Virtual Size: 0x%08X\n", pSection[i].Misc.VirtualSize);
            printf("\t- Raw Size: 0x%08X\n", pSection[i].SizeOfRawData);

            //update perms.
            pSection[i].Characteristics = dwNewFlag;
            printf("[*] New flag applied : 0x%08X\n", dwNewFlag);
            return TRUE;
        }
    }

    return FALSE;
}

int main(int argc, char *argv[]){
    if(argc != 2){
        std::cout << "[!] Error must pass one argument => <path_to_pe_file>" << std::endl;
        return EXIT_FAILURE;
    }

    //needs.
    LPSTR  lpPath    = argv[1];
    LPCSTR lpSection = ".data";
    BYTE*  pRawPe    = nullptr;
    DWORD  dwSize    = 0;

    pRawPe = ReadPeFile(lpPath, &dwSize);
    if(pRawPe == nullptr){
        std::cout << "[!] Error allocating memory" << std::endl;
        return EXIT_FAILURE;
    }

    if(!IsValidPeFile(pRawPe)){
        HeapFree(GetProcessHeap(), 0, pRawPe);
        return EXIT_FAILURE;
    }

    if(!UpdatePerm(pRawPe, dwSize, IMAGE_SCN_MEM_WRITE, lpSection)){
        std::cout << "[!] Unable to update permissions for section " << lpSection << std::endl;
        HeapFree(GetProcessHeap(), 0, pRawPe);
        return EXIT_FAILURE;
    }

    std::cout << "[*] Successfully updated permissions for section " << lpSection << std::endl;
    std::cout << "[*] Press <ENTER> to end program..." << std::endl;
    getchar();
    HeapFree(GetProcessHeap(), 0, pRawPe);
    return EXIT_SUCCESS;
}