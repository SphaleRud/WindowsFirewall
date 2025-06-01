// main.cpp (��� FirewallDaemon)
#include "firewall_daemon.h"
#include <iostream>
#include <windows.h>

int main() {
    // ������������� ���������� ��� ����������� ����������
    SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
            // ����� ����� �������� ��� ��� ����������� ����������
            return TRUE;
        }
        return FALSE;
        }, TRUE);

    FirewallDaemon daemon;

    if (!daemon.Initialize()) {
        std::cerr << "Failed to initialize firewall daemon" << std::endl;
        return 1;
    }

    std::cout << "Firewall daemon started" << std::endl;
    daemon.Run();

    return 0;
}