#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h> 
#include <ws2tcpip.h>
#include <windows.h>
#include "main_window.h"
#include "packetinterceptor.h"
#include "rule_manager.h"
#include "logger.h"

#pragma comment(lib, "ws2_32.lib")

bool IsRunAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup)) {
        dwError = GetLastError();
        goto Cleanup;
    }

    // Determine whether the SID of administrators group is enabled in 
    // the primary access token of the process.
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    if (!IsRunAsAdmin()) {
        MessageBox(NULL, L"This application must be run as administrator",
            L"Administrator Rights Required", MB_OK | MB_ICONERROR);
        return 1;
    }

    // ������� ���������� ��� �����, ���� � ���
    CreateDirectory(L"logs", NULL);

    // �������������� ������
    Logger::Instance().Initialize("logs/firewall.log");

    // �������������� ����������� �������
    auto interceptor = std::make_shared<PacketInterceptor>();
    if (!interceptor->Initialize()) {
        MessageBox(NULL, L"Failed to initialize Packet Interceptor.\nMake sure you run as Administrator.",
            L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // �������������� ������� ����
    if (!MainWindow::Instance().Initialize(hInstance, nCmdShow)) {
        MessageBox(NULL, L"Failed to initialize Main Window",
            L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // ������������� ����������� �������
    MainWindow::Instance().SetPacketInterceptor(interceptor);

    // ���������� ������� ���� � ��������� ���� ���������
    MainWindow::Instance().Show();

    // �������� ���� ���������
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}