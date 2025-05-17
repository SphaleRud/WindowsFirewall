#include "rule_manager.h"
#include <algorithm>

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

bool RuleManager::AddRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);

    // ����������� ����� ID �������
    Rule newRule = rule;
    newRule.id = nextRuleId++;

    rules.push_back(newRule);
    return true;
}

bool RuleManager::RemoveRule(int ruleId) {
    std::lock_guard<std::mutex> lock(ruleMutex);

    auto it = std::find_if(rules.begin(), rules.end(),
        [ruleId](const Rule& rule) { return rule.id == ruleId; });

    if (it != rules.end()) {
        rules.erase(it);
        return true;
    }

    return false;
}

bool RuleManager::UpdateRule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(ruleMutex);

    auto it = std::find_if(rules.begin(), rules.end(),
        [&rule](const Rule& r) { return r.id == rule.id; });

    if (it != rules.end()) {
        *it = rule;
        return true;
    }

    return false;
}

std::vector<Rule> RuleManager::GetRules() const {
    std::lock_guard<std::mutex> lock(ruleMutex);
    return rules;
}

bool RuleManager::IsAllowed(const Connection& connection, int& matchedRuleId) {
    std::lock_guard<std::mutex> lock(ruleMutex);

    for (const auto& rule : rules) {
        if (!rule.enabled) {
            continue;
        }

        // ��������� ������������ �������
        bool matches = true;

        // �������� ���������
        if (rule.protocol != Protocol::ANY && rule.protocol != connection.protocol) {
            continue;
        }

        // �������� IP-������� (���� ��� ������ � �������)
        if (!rule.sourceIp.empty() && rule.sourceIp != connection.sourceIp) {
            continue;
        }

        if (!rule.destIp.empty() && rule.destIp != connection.destIp) {
            continue;
        }

        // �������� ������ (���� ��� ������ � �������)
        if (rule.sourcePort != 0 && rule.sourcePort != connection.sourcePort) {
            continue;
        }

        if (rule.destPort != 0 && rule.destPort != connection.destPort) {
            continue;
        }

        // ���� ��� ������� �������, ��������� �������� �������
        matchedRuleId = rule.id;
        return rule.action == RuleAction::ALLOW;
    }

    // �� ���������, ���� ��� ���������� ������, ��������� ����������
    matchedRuleId = -1;
    return true;
}