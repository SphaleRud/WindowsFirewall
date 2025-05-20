#pragma once
#include <string>

enum class Protocol {
    ANY,
    TCP,
    UDP,
    ICMP
};

enum class RuleAction {
    ALLOW,
    BLOCK
};

class Rule {
public:
    Rule()
        : id(0)
        , protocol(Protocol::ANY)
        , sourcePort(0)
        , destPort(0)
        , action(RuleAction::ALLOW)
        , enabled(true)
    {
    }

    // Конструктор копирования
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
    {
    }

    // Оператор присваивания
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
        }
        return *this;
    }

    // Данные правила
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
};