#pragma once
#include "firewall_types.h"
#include <string>

class Rule {
public:
    Rule()
        : id(0)
        , protocol(Protocol::ANY)
        , sourcePort(0)
        , destPort(0)
        , action(RuleAction::ALLOW)
        , enabled(true)
        , direction(RuleDirection::Inbound)
    {
    }

    Rule(const Rule& other)
        : id(other.id)
        , name(other.name)
        , description(other.description)
        , protocol(other.protocol)
        , sourceIp(other.sourceIp)
        , destIp(other.destIp)
        , sourcePort(other.sourcePort)
        , destPort(other.destPort)
        , appPath(other.appPath)
        , action(other.action)
        , enabled(other.enabled)
        , direction(other.direction)
        , creator(other.creator)
        , creationTime(other.creationTime)
    {
    }

    Rule& operator=(const Rule& other) {
        if (this != &other) {
            id = other.id;
            name = other.name;
            description = other.description;
            protocol = other.protocol;
            sourceIp = other.sourceIp;
            destIp = other.destIp;
            sourcePort = other.sourcePort;
            destPort = other.destPort;
            appPath = other.appPath;
            action = other.action;
            enabled = other.enabled;
            direction = other.direction;
            creator = other.creator;
            creationTime = other.creationTime;
        }
        return *this;
    }

    int id;
    std::string name;
    std::string description;
    Protocol protocol;
    std::string sourceIp;
    std::string destIp;
    int sourcePort;
    int destPort;
    std::string appPath;
    RuleAction action;
    bool enabled;
    RuleDirection direction;
    std::string creator;
    std::string creationTime;
};