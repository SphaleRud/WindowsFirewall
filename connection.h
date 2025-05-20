#pragma once
#include "firewall_types.h"
#include <string>

struct Connection {
    Protocol protocol;
    std::string sourceIp;
    std::string destIp;
    int sourcePort;
    int destPort;
    std::string appPath;

    Connection()
        : protocol(Protocol::ANY)
        , sourcePort(0)
        , destPort(0)
    {
    }
};