/**
 * Add a new section
 */
#include "global.hpp"
#include "peLib.hpp"

/**
 * Add a new section to a PE FILE.
 */
static BOOL AddSection(IN LPCSTR lpPath, IN LPCSTR lpSectionName, IN DWORD dwSize){
    HANDLE hFile    = nullptr;
    BOOL   state    = TRUE;
    BYTE*  pEmpty   = nullptr;

    DWORD  dwOffset   = 0;
    DWORD  fAlignment = 0;
    DWORD  sAlignment = 0;

    IMAGE_DOS_HEADER     dos        = {0};
    IMAGE_NT_HEADERS     ntH        = {0};
    IMAGE_SECTION_HEADER newSection = {0};

    RtlSecureZeroMemory(&dos, sizeof(IMAGE_DOS_HEADER));
    RtlSecureZeroMemory(&ntH, sizeof(IMAGE_NT_HEADERS));

    std::cout << "[*] Opening file..." << std::endl;
    hFile = CreateFileA(lpPath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE){
        std::cout << "[!] Error calling CreateFileA with error : " << GetLastError() << std::endl;
        return FALSE;
    }

    if(!ReadFile(hFile, &dos, sizeof(IMAGE_DOS_HEADER), nullptr, nullptr)){
        std::cout << "[!] Error reading file." << std::endl;
        state = FALSE; goto _Cleanup;
    }

    if(dos.e_magic != IMAGE_DOS_SIGNATURE || SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER){
        std::cout << "[!] Bad PE file." << std::endl;
        state = false; goto _Cleanup;
    }

    //reading nt header
    if(!ReadFile(hFile, &ntH, sizeof(IMAGE_NT_HEADERS), nullptr, nullptr)){
        std::cout << "[!] Error reading file." << std::endl;
        state = FALSE; goto _Cleanup;
    }

    std::cout << "[*] Successfully read headers" << std::endl;
    std::cout << "[*] Creating new section" << std::endl;

    dwOffset = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (ntH.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    RtlSecureZeroMemory(&newSection, sizeof(IMAGE_SECTION_HEADER));

    //setup struct.
    fAlignment = ntH.OptionalHeader.FileAlignment;
    sAlignment = ntH.OptionalHeader.SectionAlignment;

    strncpy((char*)newSection.Name, lpSectionName, sizeof(newSection.Name));

    newSection.Misc.VirtualSize = dwSize;
    newSection.SizeOfRawData = (dwSize + fAlignment - 1) & ~(fAlignment - 1);
    newSection.PointerToRawData = (ntH.OptionalHeader.SizeOfImage + fAlignment - 1) & ~(fAlignment - 1);
    newSection.VirtualAddress = (ntH.OptionalHeader.SizeOfImage + sAlignment - 1) & ~(sAlignment - 1);
    newSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    ntH.FileHeader.NumberOfSections++;
    ntH.OptionalHeader.SizeOfImage = newSection.VirtualAddress + ((dwSize + sAlignment - 1) & ~(sAlignment - 1));

    std::cout << "[!] Applying updates" << std::endl;

    SetFilePointer(hFile, dos.e_lfanew, NULL, FILE_BEGIN);
    if(!WriteFile(hFile, &ntH, sizeof(IMAGE_NT_HEADERS), nullptr, nullptr)){
        state = FALSE; goto _Cleanup;
    }

    SetFilePointer(hFile, dwOffset, nullptr, FILE_BEGIN);
    if(!WriteFile(hFile, &newSection, sizeof(IMAGE_SECTION_HEADER), nullptr, nullptr)){
        state = FALSE; goto _Cleanup;
    }

    SetFilePointer(hFile, newSection.PointerToRawData, NULL, FILE_BEGIN);
    pEmpty = new BYTE[newSection.SizeOfRawData]();

    if (!WriteFile(hFile, pEmpty, newSection.SizeOfRawData, nullptr, nullptr)) {
        std::cout << "[!] Failed to write section data." << std::endl;
        state = FALSE;
    }

_Cleanup:
    if(hFile){
        SetEndOfFile(hFile);
        CloseHandle(hFile);
    }

    if(pEmpty != nullptr){
        delete[] pEmpty;
    }

    return state;
}

int main(int argc, char *argv[]){
    if(argc != 2){
        std::cout << "[!] Error : must pass one argument => <path_to_pe_file>" << std::endl;
        return EXIT_FAILURE;
    }

    LPCSTR lpNewSection = ".new"; // set your own. => MAX 8 characters !
    LPCSTR lpPath       = argv[1];

    if(!AddSection(lpPath, lpNewSection, 4096)){
        return EXIT_FAILURE;
    }

    std::cout << "[*] Successfully added new section" << std::endl;
    std::cout << "[$] Presse <ENTER> to end program." << std::endl;
    getchar();
    return EXIT_SUCCESS;
}