#include <windows.h>
#include "function-resolution.h"

// Parameter struct for passing to the run function.
typedef struct Params
{
    LPVOID pBaseAddress;
    LPVOID pMessageBox;
    DWORD  dwSleepTime;
} PARAMS;

// Message box function pointer.
typedef int (*fpMessageBoxA)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

// VirtualProtect function pointer.
typedef BOOL (*fpVirtualProtect)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

// Sleep function pointer.
typedef void (*fpSleep)(
  DWORD dwMilliseconds
);

// djb2 hashes for dynamic function resolution.
#define VirtualProtect_HASH 0xc25aaa07
#define KERNEL32DLL_HASH1   0xa709e74f /// Hash of KERNEL32.DLL
#define KERNEL32DLL_HASH2   0xa96f406f /// Hash of kernel32.dll
#define KERNEL32DLL_HASH3   0x8b03944f /// Hash of Kernel32.dll
#define Sleep_HASH          0xa8d9dd38

// XOR a buffer with a single byte key.
VOID XORSingle( CHAR szInput[], SIZE_T nLength, BYTE cKey );

// Round a value to the nearest multiple. For rounding to the nearest 4k page.
ULONGLONG RoundUp( ULONGLONG numToRound, ULONGLONG multiple);

// XOR encrypt a section.
BOOL EncryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect );

// XOR decrypt a section.
BOOL DecryptSection( LPVOID pSectionAddress, DWORD dwSectionLen, DWORD dwProtection, fpVirtualProtect _VirtualProtect );
