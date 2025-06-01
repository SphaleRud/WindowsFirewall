// firewall_daemon.h
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "rule.h"
#include "wfp_blocker.h"

class FirewallDaemon {
public:
    FirewallDaemon();
    ~FirewallDaemon();

    bool Initialize();
    void Run();
    void Stop();

private:
    bool running;
    WfpBlocker wfpBlocker;
    HANDLE pipeHandle;
    static const std::wstring PIPE_NAME;

    bool CreateNamedPipe();
    bool HandleCommand(const std::string& command, const Rule& rule);
    bool ProcessClientConnection();
};