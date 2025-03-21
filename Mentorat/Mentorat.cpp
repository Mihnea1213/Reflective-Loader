#include <iostream>
#include <Windows.h>
#include <cstring>

FARPROC GetProcAddress_secundar(HMODULE hModule, const char* procName) {
    if (!hModule || !procName) {
        return nullptr;
    }

    // Obține antetul NT al modulului
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    // Găsește tabela de export
    IMAGE_DATA_DIRECTORY exportDirectoryData = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectoryData.VirtualAddress == 0) {
        return nullptr; // Nu există tabelă de export
    }

    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + exportDirectoryData.VirtualAddress);

    // Obține pointerii către funcții, nume și ordinale
    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    WORD* addressOfOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

    // Caută funcția în tabelă
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + addressOfNames[i]);
        if (_stricmp(functionName, procName) == 0) { // Comparare fără case sensitivity
            WORD ordinalIndex = addressOfOrdinals[i];
            DWORD functionRVA = addressOfFunctions[ordinalIndex];
            return (FARPROC)((BYTE*)hModule + functionRVA);
        }
    }

    return nullptr; // Funcția nu a fost găsită
}

bool VerifyMZPE(HANDLE hfile, LPVOID& buffer, DWORD& fileSize)
{
    DWORD bytesRead;
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadFile(hfile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) || bytesRead != sizeof(dosHeader))
    {
        std::cerr << "Eroare1";
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Eroare2";
        return false;
    }
    DWORD peOffset = dosHeader.e_lfanew;
    SetFilePointer(hfile, peOffset, nullptr, FILE_BEGIN);
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadFile(hfile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr) || bytesRead != sizeof(ntHeaders))
    {
        std::cerr << "Eroare3";
        return false;
    }
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Eroare4";
        return false;
    }
    buffer = VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        std::cerr << "Eroare5";
        return false;
    }
    SetFilePointer(hfile, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(hfile, buffer, fileSize, &bytesRead, nullptr))
    {
        std::cerr << "Eroare6";
        return false;
    }
    std::cout << "File read succesfully";
    return true;
}

void ParseAndExecutePE(LPVOID fileBuffer) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)fileBuffer + dosHeader->e_lfanew);

    // Alocă memorie la adresa de bază specificată în header
    PBYTE mem = (PBYTE)VirtualAlloc((void*)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == 0) {
        std::cerr << "Failed to allocate memory for binary!\n";
        return;
    }

    // Copiază conținutul fișierului în memoria alocată
    memcpy(mem, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Procesează secțiunile și le copiază în memoria alocată
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        memcpy(mem + sectionHeader[i].VirtualAddress, (BYTE*)fileBuffer + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);
    }

    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0)
    {
        std::cerr << "Eroare11";
        return;
    }
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(mem + importDirectory.VirtualAddress);
    while (importDescriptor->Name != 0)
    {
        char* dllName = (char*)(mem + importDescriptor->Name);
        HMODULE hmodule = LoadLibraryA(dllName);
        if (!hmodule)
        {
            std::cerr << "Eroare12";
            return;
        }
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(mem + importDescriptor->OriginalFirstThunk);
        IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)(mem + importDescriptor->FirstThunk);
        while (thunk->u1.AddressOfData != 0)
        {
            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(mem + thunk->u1.AddressOfData);
                FARPROC procAdress = GetProcAddress(hmodule, importByName->Name); //Se poate utiliza si GetProcAddress_secundar aici
                if (!procAdress)
                {
                    std::cerr << "Eroare13";
                    return;
                }
                firstThunk->u1.Function = (ULONGLONG)procAdress;
            }
            else
            {
                std::cerr << "Eroare14";
                return;
            }
            ++thunk;
            ++firstThunk;
        }
        ++importDescriptor;
    }

    // Calculează adresa de intrare și apelează funcția
    LPVOID entryPoint = mem + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    auto func = (void(*)())entryPoint;
    func();
    std::cout << "Calculatorul a fost lansat!" << std::endl;
}

int main()
{
    const char* filePath = "C:\\Windows\\System32\\calc.exe";
    HANDLE hfile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hfile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Eroare";
        return 1;
    }
    LPVOID fileBuffer;
    DWORD fileSize;
    if (!VerifyMZPE(hfile, fileBuffer, fileSize))
    {
        CloseHandle(hfile);
        return 1;
    }
    ParseAndExecutePE(fileBuffer);
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    CloseHandle(hfile);
    return 0;
}