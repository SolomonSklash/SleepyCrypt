#include "run.h"

VOID run( PARAMS pParams )
{
    // Save the base address.
    PIMAGE_DOS_HEADER     pDosHeader     = pParams.pBaseAddress;
    PIMAGE_NT_HEADERS64   pNtHeaders     = NULL;
	PIMAGE_FILE_HEADER    pFileHeader    = NULL;
    PIMAGE_SECTION_HEADER pFirstSection  = NULL;

    // Array for storing the different memory protection values for each section.
    // This assumes there will not be more than 256 sections, which would be crazy...
    DWORD dwProtectionArr[256];

    // Save the sleep time.
    DWORD dwSleepTime = pParams.dwSleepTime;

    // Save the message box function pointer.
    fpMessageBoxA    _MessageBoxA    = pParams.pMessageBox;

    // Create dynamically resolved function pointers.
    fpVirtualProtect _VirtualProtect = NULL;
    fpSleep          _Sleep          = NULL;

    // Dynamically resolve needed functions via djb2 hash.
    #pragma region function-resolution
    /// Resolve the address of KERNEL32.DLL via djb2 hash.
    LPVOID pKernel32Dll = NULL;
    pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH1 );
    if ( NULL == pKernel32Dll )
    {
        /// Resolve the address of kernel32.dll via djb2 hash.
        pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH2 );
        if ( NULL == pKernel32Dll )
        {
            /// Resolve the address of Kernel32.dll via djb2 hash.
            pKernel32Dll = GetModuleByHash( KERNEL32DLL_HASH3 );
            if ( NULL == pKernel32Dll ) {
                return;
            }
        }
    }
    
    /// Resolve the address of VirtualProtect via djb2 hash.
    _VirtualProtect = GetProcAddressByHash( pKernel32Dll, VirtualProtect_HASH );
    if ( NULL == _VirtualProtect ) {
        return;
    }
    
    /// Resolve the address of Sleep via djb2 hash.
    _Sleep = GetProcAddressByHash( pKernel32Dll, Sleep_HASH );
    if ( NULL == _Sleep ) {
        return;
    }
    #pragma endregion function-resolution

    // Get a pointer to the NT header.
	pNtHeaders = ( PIMAGE_NT_HEADERS64 )(( PBYTE )pDosHeader + ( DWORD )pDosHeader->e_lfanew);

    // Get a pointer to the file header.
	pFileHeader = &(pNtHeaders->FileHeader);

    // Get the offset of the beginning of section headers/first section header.
	pFirstSection = ( PIMAGE_SECTION_HEADER )(( ULONGLONG ) & (pNtHeaders->OptionalHeader) + pFileHeader->SizeOfOptionalHeader);
    
    // Pop message box to say we're about to start encrypting.
    CHAR szEncrypting[] = { 'E', 'n', 'c', 'r', 'y', 'p', 't', 'i', 'n', 'g', 0x0 };
    CHAR szTitle[]      = { 'S', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', 0x0 };
    _MessageBoxA( NULL, szEncrypting, szTitle, 0 );

    // Parse and print data for each section.
	for ( WORD i = 0; i < pFileHeader->NumberOfSections; i++ )
	{    
        // Get the virtual address of the current section.
        PIMAGE_SECTION_HEADER pSectionHeader = ( PIMAGE_SECTION_HEADER )(( ULONGLONG )pFirstSection 
                                             + ( IMAGE_SIZEOF_SECTION_HEADER * i));
		
        // Skip empty sections
        if ( pSectionHeader->PointerToRawData == 0 || pSectionHeader->SizeOfRawData == 0 ) {
			continue; 
        }

        // Get the actual VA of the section start.
        LPVOID lpSectionAddress = ( PIMAGE_SECTION_HEADER )(( UINT64 )pDosHeader 
                                + ( UINT64 )pSectionHeader->VirtualAddress);

        // Get the section characteristics field.
        DWORD dwCharacteristics = pSectionHeader->Characteristics;
        
        // Find the actual memory protection of the section.
        /*
            0x20000000 = IMAGE_SCN_MEM_EXECUTE = Executable
            0x40000000 = IMAGE_SCN_MEM_READ    = Readable
            0x80000000 = IMAGE_SCN_MEM_WRITE   = Writable
        */
        // Right shift 28 bits to get just the protection value as a DWORD.
        DWORD dwShifted = dwCharacteristics >> 28;

        // Switch on the memory protection value and save it in the protection array.
        switch ( dwShifted )
        {
            case 0x2: // X
                dwProtectionArr[i] = PAGE_EXECUTE;
                break;
            case 0x4:// R
                dwProtectionArr[i] = PAGE_READONLY;
                break;
            case 0x6: // R+X
                dwProtectionArr[i] = PAGE_EXECUTE_READ;
                break;
            case 0xC: // R+W
                dwProtectionArr[i] = PAGE_READWRITE;
                break;
            default:
                break;
        }

        // Encrypt each section.
        if ( !EncryptSection( lpSectionAddress, ( DWORD )RoundUp( pSectionHeader->Misc.VirtualSize, 0x1000 ), 
                              PAGE_READWRITE, _VirtualProtect )) {
            return;
        }
    }

    // Encrypt the PE header page. It is 1 page/4k long.
    if ( !EncryptSection( pDosHeader, 0x1000, PAGE_READWRITE, _VirtualProtect )) {
        return;
    }

    // Sleep for pParams.dwSleepTime milliseconds.
    _Sleep( dwSleepTime );

    // Pop message box to say we're about to start decrypting.
    CHAR szDecrypting[] = { 'D', 'e', 'c', 'r', 'y', 'p', 't', 'i', 'n', 'g', 0x0 };
    _MessageBoxA( NULL, szDecrypting, szTitle, 0 );

    // Decrypt the PE header page. This must be done before the other sections,
    // as the PE headers are needed to parse the sections.
    if ( !DecryptSection( pDosHeader, 0x1000, PAGE_READONLY, _VirtualProtect )) {
        return;
    }

    // Decrypt each section and restore its memory protections.
	for ( WORD i = 0; i < pFileHeader->NumberOfSections; i++ )
	{    
        // Get the address of the current section.
        PIMAGE_SECTION_HEADER pSectionHeader = ( PIMAGE_SECTION_HEADER )(( ULONGLONG )pFirstSection
                                             + (IMAGE_SIZEOF_SECTION_HEADER * i));
		
        // Skip empty sections.
        if ( pSectionHeader->PointerToRawData == 0 || pSectionHeader->SizeOfRawData == 0 ) {
			continue; 
        }

        // Get the actual address of the section start. Base address + VA.
        LPVOID lpSectionAddress = ( PIMAGE_SECTION_HEADER )(( UINT64 )pDosHeader
                                + ( UINT64 )pSectionHeader->VirtualAddress);

        // Decrypt each section, rounding the size up to the nearest 4k page.
        if ( !DecryptSection( lpSectionAddress, ( DWORD )RoundUp( pSectionHeader->Misc.VirtualSize, 0x1000 ), 
                              dwProtectionArr[i], _VirtualProtect )) {
            return;
        }
    }

    // Done!
    CHAR szDone[]  = { 'D', 'o', 'n', 'e', 0x0 };
    _MessageBoxA( NULL, szDone, szTitle, 0 );

    return;
}

// XOR a buffer with a static 1 byte key.
VOID XORSingle( CHAR szInput[], SIZE_T nLength, BYTE cKey )
{
    for ( SIZE_T i = 0; i < nLength; i++ )
    {
        szInput[i] = ( BYTE )szInput[i] ^ cKey;
    }
}

// Round a value to the nearest multiple. For rounding to the nearest 4k page.
// Bit twiddling magic taken from Stack Overflow...
// https://stackoverflow.com/a/9194117
ULONGLONG RoundUp( ULONGLONG numToRound, ULONGLONG multiple) 
{
    return ( numToRound + multiple - 1 ) & -multiple;
}

// XOR encrypt a section. Takes the address of VirtualProtect so we don't have to resolve it.
BOOL EncryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect )
{
    // Change the protection of section to RW.
    DWORD dwOldProtect = 0;
    if ( !_VirtualProtect( pSectionAddress, dwSectionLen, dwProtection, &dwOldProtect )) {
        return FALSE;
    }

    // XOR the section with a static 1 byte key.
    XORSingle( (PCHAR)pSectionAddress, dwSectionLen, 0x4C );
    return TRUE;
}

// XOR decrypt a section. Takes the address of VirtualProtect so we don't have to resolve it.
BOOL DecryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect )
{
    // XOR the section with a static 1 byte key. The memory protection should already be RW.
    XORSingle( (PCHAR)pSectionAddress, dwSectionLen, 0x4C );

    // Change the protection of the section back to the original protection.
    DWORD dwOldProtect = 0;
    if ( !_VirtualProtect( pSectionAddress, dwSectionLen, dwProtection, &dwOldProtect )) {
        return FALSE;
    }
    return TRUE;
}