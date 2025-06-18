#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h> 
#include <ws2tcpip.h>
#include <windows.h>
#include "main_window.h"
#include "packetinterceptor.h"
#include "rule_manager.h"
#include "logger.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "ws2_32.lib")

// Проверка прав администратора
bool IsRunAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup)) {
        dwError = GetLastError();
        goto Cleanup;
    }

    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }
    return fIsRunAsAdmin;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    try {
        INITCOMMONCONTROLSEX icc;
        icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES;
        InitCommonControlsEx(&icc);

        MainWindow mainWindow;
        if (!mainWindow.Initialize(hInstance)) {
            MessageBox(NULL, L"Failed to initialize window", L"Error", MB_OK | MB_ICONERROR);
            return 1;
        }

        mainWindow.Show(nCmdShow);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        return static_cast<int>(msg.wParam);
    }
    catch (const std::exception& e) {
        std::string error = "Unhandled exception: " + std::string(e.what());
        OutputDebugStringA(error.c_str());
        MessageBoxA(NULL, error.c_str(), "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
}