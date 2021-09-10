/**
 * @file function-resolution.h
 * Implementation for dynamic function resolution.
 * From https://github.com/jeremybeaume/experiments/blob/master/no_imports/noimport.c
 */
#pragma once
#ifndef FUNCTION_RESOLUTION_H
#define FUNCTION_RESOLUTION_H
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef struct _LDR_DATA_TABLE_ENTRY_COMPLETED
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     // The rest is not used.
} LDR_DATA_TABLE_ENTRY_COMPLETED, *PLDR_DATA_TABLE_ENTRY_COMPLETED;

/*  strcmp reimplementation. Returns true/false.  */
int _strcmp( PCHAR cmp, PCHAR other )
{
    while( *other == *cmp && *other != 0 )
    {
        cmp++;
        other++;
    }
    return ( *cmp == *other );
}

/*  wcsicmp reimplementation, cmp must be lowercase. Returns true/false.  */
int _wstrcmpi( WCHAR* cmp, WCHAR* other )
{
    PWORD w_cmp   = (PWORD) cmp;
    PWORD w_other = (PWORD) other;
    while( *w_other != 0 )
    {
        WORD lowercase_other = ( (*w_other>='A' && *w_other<='Z')
                                 ? *w_other - 'A' + 'a'
                                 : *w_other);
        if( *w_cmp != lowercase_other ) {
            return 0;
        }
        w_cmp ++;
        w_other ++;
    }
    return ( *w_cmp == 0 );
}

/*  Find module address by reading the PEB. pwModuleName must be lowercase.  */
LPVOID _GetModuleHandleW( WCHAR* pwModuleName )
{
    // Get the PEB address from the TEB
    PEB* PEB_ptr = NULL;
    #if defined(_WIN64)
    PEB_ptr = (PEB*)__readgsqword(0x60);
    #else
    PEB_ptr = (PEB*)__readfsdword(0x30);
    #endif

    /// Get the module linked list.
    PEB_LDR_DATA* peb_ldr_data = PEB_ptr->Ldr;
    LIST_ENTRY*   list_head    = &(peb_ldr_data->InMemoryOrderModuleList);
    LIST_ENTRY*   list_entry;
    LDR_DATA_TABLE_ENTRY_COMPLETED* ldr_entry;

    /// Go through the linked list to find kernel32.dll.
    /// Stops when return to header element (the list head is linked to the tail).
    for ( list_entry = list_head->Flink; list_entry != list_head; list_entry = list_entry->Flink )
    {
        /// We follow inMemoryOrder, so list_entry points to LDR_DATA_TABLE_ENTRY_COMPLETED.InMemoryOrderLinks
        /// We need to remove the size of the first element to get the address of the object
        ldr_entry = (LDR_DATA_TABLE_ENTRY_COMPLETED*) ((PCHAR)list_entry - sizeof( LIST_ENTRY ));
        WCHAR* pwDllName = ldr_entry->BaseDllName.Buffer;
        if ( _wstrcmpi( pwModuleName, pwDllName )) {
            return ldr_entry->DllBase;
        }
    }
    return NULL;
}

/*  Find an exported function of a module by name.  */
LPVOID _GetProcAddress( LPVOID lpModuleAddress, PCHAR pFunctionName )
{

    /// Get the export table.
    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*) lpModuleAddress;
    IMAGE_NT_HEADERS* p_NT_HDR  = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*) ((UINT64)lpModuleAddress +
            p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    /// Get the arrays based on their RVA in the IMAGE_EXPORT_DIRECTORY struct.
    PDWORD names_RVA_array    = (PDWORD)((UINT64)lpModuleAddress + export_directory->AddressOfNames);
    PDWORD function_RVA_array = (PDWORD)((UINT64)lpModuleAddress + export_directory->AddressOfFunctions);
    PWORD name_ordinals_array = (PWORD) ((UINT64)lpModuleAddress + export_directory->AddressOfNameOrdinals);

    /// For each function get the functions ordinal, name and code RVA.
    /// DWORD exported_ordinal = name_ordinals_array[i] + export_directory->Base;
    for ( int i = 0; i < export_directory->NumberOfFunctions; ++i )
    {
        PCHAR funct_name = (UINT64)lpModuleAddress + names_RVA_array[i];
        DWORD exported_RVA = function_RVA_array[name_ordinals_array[i]];

        if ( _strcmp( pFunctionName, funct_name )) {
            return (LPVOID) ((UINT64)lpModuleAddress + exported_RVA);
        }
    }
    return NULL;
}

/**  djb2 hash for wide strings, modified to avoid the signature constant of 5381.
     https://theartincode.stanis.me/008-djb2/
*/
UINT djb2HashW( WCHAR* str )
{
    // UINT hash = 5381;
    UINT hash = 8191;
    INT c;

    while ( (c = *str++) )
    {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

/**  djb2 hash for ANSI strings, modified to avoid the signature constant of 5381.
     https://theartincode.stanis.me/008-djb2/
*/
UINT djb2HashA( PCHAR str )
{
    // UINT hash = 5381;
    UINT hash = 8191;
    INT c;

    while ( (c = *str++) )
    {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

/**  Get the address of a *loaded* module by djb2 hash.  */
LPVOID GetModuleByHash( UINT unModuleHash )
{
    /// Get the PEB address from the TEB. X64 only.
    PEB* PEB_ptr = NULL;
    PEB_ptr = (PEB*)__readgsqword( 0x60 );
    if ( NULL == PEB_ptr ) {
        return NULL;
    }

    /// Get the module linked list.
    PEB_LDR_DATA* pPebLdrData = PEB_ptr->Ldr;
    LIST_ENTRY*   pListHead   = &( pPebLdrData->InMemoryOrderModuleList );
    LIST_ENTRY*   pListEntry  = NULL;
    LDR_DATA_TABLE_ENTRY_COMPLETED* pLdrEntry;

    /// Go through the linked list to find the target module hash.
    /// Stops when return to header element (the list head is linked to the tail).
    for ( pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink )
    {
        /// We follow inMemoryOrder, so list_entry points to LDR_DATA_TABLE_ENTRY_COMPLETED.InMemoryOrderLinks
        /// We need to remove the size of the first element to get the address of the object
        pLdrEntry = (LDR_DATA_TABLE_ENTRY_COMPLETED*) ((PCHAR)pListEntry - sizeof( LIST_ENTRY ));
        WCHAR* pwDllName = pLdrEntry->BaseDllName.Buffer;

        /// Calculate the hash of kernel32.dll.
		UINT unHash = djb2HashW( pwDllName );

		/// Compare the hash to the target module hash.
		if ( unHash == unModuleHash )
        {
            /// Return module address if found.
            // printf( "Found! DJB result: %x\n", unHash );
            return pLdrEntry->DllBase;
        }
    }
    /// Return NULL if the module is not found.
    return NULL;
}

/**  Get the address of an exported function from a *loaded* module by djb2 hash.  */
LPVOID GetProcAddressByHash( LPVOID lpModuleAddress, UINT unFunctionHash )
{
    /// Get the export table.
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*) lpModuleAddress;
    IMAGE_NT_HEADERS* pNtHeader  = (IMAGE_NT_HEADERS*) (((char*) pDosHeader) + pDosHeader->e_lfanew );
    IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*) ((UINT64)lpModuleAddress +
            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

    /// Get the arrays based on their RVA in the IMAGE_EXPORT_DIRECTORY struct.
    PDWORD pdwNamesArray        = (PDWORD)((UINT64)lpModuleAddress + pExportDirectory->AddressOfNames );
    PDWORD pdwFunctionArray     = (PDWORD)((UINT64)lpModuleAddress + pExportDirectory->AddressOfFunctions );
    PWORD  pdwNameOrdinalsArray = (PWORD) ((UINT64)lpModuleAddress + pExportDirectory->AddressOfNameOrdinals );

    /// For each function get the function's ordinal, name and code RVA.
    for ( int i = 0; i < pExportDirectory->NumberOfFunctions; ++i )
    {
        PCHAR pFunctionName = (UINT64)lpModuleAddress + pdwNamesArray[i];
        DWORD exported_RVA  = pdwFunctionArray[pdwNameOrdinalsArray[i]];

        /// Calculate the hash of kernel32.dll.
		unsigned int unHash = djb2HashA( pFunctionName );

		/// Compare the hash to known kernel32.dll hash.
		if ( unHash == unFunctionHash )
        {
            /// Return function address if found.
            // printf( "Found! DJB result: %x\n", unHash );
            return (LPVOID)((UINT64)lpModuleAddress + exported_RVA );
        }
    }
    /// Return NULL if the function is not found.
    return NULL;
}

#endif /*  FUNCTION_RESOLUTION_H  */
