#pragma once
#include <vector>
#include <mutex>
#include "types.h"

class RuleManager {
private:
    // Приватный конструктор для синглтона
    RuleManager() = default;
    ~RuleManager() = default;

    std::vector<Rule> rules;
    mutable std::mutex ruleMutex;
    int nextRuleId = 1;

public:
    // Запрещаем копирование и присваивание
    RuleManager(const RuleManager&) = delete;
    RuleManager& operator=(const RuleManager&) = delete;

    // Методы синглтона
    static RuleManager& Instance();

    // Методы управления правилами
    bool AddRule(const Rule& rule);
    bool RemoveRule(int ruleId);
    bool UpdateRule(const Rule& rule);
    std::vector<Rule> GetRules() const;
    bool IsAllowed(const Connection& connection, int& matchedRuleId);
};