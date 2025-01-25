/**
 * NOTES : => DUMP SECTIONS FROM RAW PE.
 */

#include "global.hpp"
#include "peLib.hpp"

/**
 * DUMP section from a raw pe file.
 */
static VOID DumpSection(IN BYTE* pRawPe, LPSTR lpSection){
    PIMAGE_NT_HEADERS pNtHdr       = GetNtHdr(pRawPe);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);

    if(pSection == nullptr)
        return;
    
    size_t sLpSize = strlen(lpSection);

    if(sLpSize > 8)
        return; //max section name => 8

    for(WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++){
        BYTE* pSectionName = (BYTE*)pSection[i].Name;
        if(memcmp(pSectionName, lpSection, sLpSize) == 0){
            std::cout << "[*] Found " << lpSection << " section" << std::endl;
            printf("\t- Virtual Size: 0x%08X\n", pSection[i].Misc.VirtualSize);
            printf("\t- Raw Size: 0x%08X\n", pSection[i].SizeOfRawData);

            std::cout << "\n-------------------DUMPING SECTION-------------------" << std::endl;
            BYTE* pStartSection = ((BYTE*)pRawPe + pSection[i].PointerToRawData);
            for(DWORD j = 0; j < pSection[i].SizeOfRawData; j++){
                if(j % 16 == 0) printf("\n%04X: ", j);
                printf("%02X ", pStartSection[j]);
            }

            printf("\n");
            std::cout << "-----------------------------------------------------" << std::endl;
            return;
        }
    }

    std::cout << "[!] " << lpSection << " not found..." << std::endl;
}

//entry point.
int main(int argc, char *argv[]){
    if(argc != 2){
        std::cout << "[!] Error : must pass one argument => <path_to_pe_file>" << std::endl;
        return EXIT_FAILURE;
    }

    LPSTR lpPath = argv[1];
    LPSTR lpType = ".data"; //define your section choice to dump.

    BYTE* pRawPe = nullptr;
    DWORD dwSize = 0;

    pRawPe = ReadPeFile(lpPath, &dwSize);
    if(pRawPe == nullptr){
        std::cout << "[!] Error reading pe file." << std::endl;
        return EXIT_FAILURE;
    }

    if(!IsValidPeFile(pRawPe)){
        printf("[!] Not a valid PE file...\n");
        HeapFree(GetProcessHeap(), 0, pRawPe);
        return EXIT_FAILURE;
    }

    printf("[*] Read %s & %d bytes of memory written.\n", lpPath, dwSize);
    printf("[$] Press <ENTER> to read %s section...  \n", lpType);
    getchar();

    //dump section.
    DumpSection(pRawPe, lpType);

    printf("[$] Presse <ENTER> to end program...\n");
    getchar();
    HeapFree(GetProcessHeap(), 0, pRawPe);
    return EXIT_SUCCESS;
}