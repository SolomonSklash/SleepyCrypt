#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

// Struct to pass parameters to the run function shellcode.
typedef struct Params
{
    // Base address of the image to encrypt.
    LPVOID pBaseAddress; 
    // Dynamically resolved MessageBoxA for debugging inside the shellcode.
    LPVOID pMessageBox;
    // Time to sleep for inside the shellcode.
    DWORD  dwSleepTime;
} PARAMS;

// Define the function pointer to the run function.
typedef VOID (*fprun)( PARAMS pParams );

int main( int argc, char* argv[] )
{
    // Check for sleep time.
    if ( 1 == argc ) {
        printf( "[!] Please provide number of milliseconds to sleep\n" );
        exit( 1 );
    }
    // Save sleep time.
    DWORD dwSleepTime = ( DWORD )atoi( argv[1] );
    
    // Create struct argument for the run function shellcode.
    PARAMS pParams;

    // Dynamically resolve message box so the shellcode doesn't have to.
    LoadLibraryA( "User32.dll" );
    LPVOID pMessageBox = ( LPVOID )GetProcAddress( GetModuleHandleA("User32.dll"), "MessageBoxA" );

    // Set the base address of the current image.
    pParams.pBaseAddress = ( LPVOID )GetModuleHandleA( NULL );
    // Set the sleep time.
    pParams.dwSleepTime = dwSleepTime;
    // Set the message box function address.
    pParams.pMessageBox = pMessageBox;

    printf( "[+] Current image base address = 0x%p\n", pParams.pBaseAddress );

    // Create RWX space. IOC.
    LPVOID pBuffer = VirtualAlloc( NULL, shellcode_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( NULL == pBuffer ) {
        printf( "[!] VirtualAlloc failed\n" );
        exit(1);
    }

    // Copy the shellcode into it.
    memcpy( pBuffer, shellcode_bin, shellcode_bin_len );

    // Make a function pointer to the run function shellcode.
    fprun Run = ( fprun )pBuffer;

    // Call the run function shellcode after pressing a key.
    printf( "[+] Press a key to sleep for %ld ms\n", pParams.dwSleepTime );
    getchar();
    
    Run( pParams );

    // Done!
    printf( "[+] Awake again! Press another key to exit " );
    getchar();

    return 0;
}