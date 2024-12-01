#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <sddl.h>
#include <iostream>
#include <string>

#define SIOCTL_TYPE 40000
#define IOCTL_HELLO CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

void GetCurrentUserSID(char* sidBuffer, size_t bufferSize) {
    HANDLE hToken = NULL;
    DWORD dwBufferSize = 0;
    PTOKEN_USER pTokenUser = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl; // 오류 출력
        return;
    } // 현재 실행 중인 프로세스의 보안 토큰을 연다.

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize); // TokenUser의 정보를 요청
    pTokenUser = static_cast<PTOKEN_USER>(malloc(dwBufferSize));    // TokenUser 구조체 동적할당
    // TokenUser는 SID를 가지고 있음

    if (pTokenUser == NULL) {
        std::cerr << "Memory allocation failed." << std::endl;
        CloseHandle(hToken);
        return;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        std::cerr << "GetTokenInformation failed. Error: " << GetLastError() << std::endl;
        free(pTokenUser);
        CloseHandle(hToken);
        return;
    }

    LPSTR sidString = NULL;
    if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
        strncpy_s(sidBuffer, bufferSize, sidString, _TRUNCATE);
        LocalFree(sidString);
    }
    else {
        std::cerr << "ConvertSidToStringSid failed. Error: " << GetLastError() << std::endl;
    } // SID를 문자열로 전환

    free(pTokenUser);
    CloseHandle(hToken);
}

int main(int argc, char* argv[]) {
    HANDLE hDevice;
    char sidBuffer[128] = { 0 };
    char ReadBuffer[50] = { 0 };
    DWORD dwBytesRead = 0;

    GetCurrentUserSID(sidBuffer, sizeof(sidBuffer));
    std::cout << "Current User SID: " << sidBuffer << std::endl;

    hDevice = CreateFile(L"\\\\.\\MyDevice", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    std::cout << "Handle : " << hDevice << std::endl;

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    if (!DeviceIoControl(hDevice, IOCTL_HELLO, sidBuffer, static_cast<DWORD>(strlen(sidBuffer) + 1), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL)) {
        std::cerr << "DeviceIoControl failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "Message received from kernel: " << ReadBuffer << std::endl;
    std::cout << "Bytes read: " << dwBytesRead << std::endl; // SID를 커널 드라이버로 전달

    CloseHandle(hDevice);

    return 0;
}
