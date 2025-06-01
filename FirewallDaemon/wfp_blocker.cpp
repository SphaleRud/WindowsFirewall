#include "wfp_blocker.h"
#include <ws2tcpip.h>

WfpBlocker::WfpBlocker() : engineHandle(NULL) {}

WfpBlocker::~WfpBlocker() {
    RemoveAllRules();
    if (engineHandle) {
        FwpmEngineClose0(engineHandle);
    }
}

bool WfpBlocker::Initialize() {
    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle) == ERROR_SUCCESS;
}

void WfpBlocker::RemoveAllRules() {
    if (!engineHandle) return;

    for (auto id : filterIds) {
        FwpmFilterDeleteById0(engineHandle, id);
    }
    filterIds.clear();
}

bool WfpBlocker::ApplyRule(const Rule& rule) {
    if (!engineHandle) return false;

    if (!rule.appPath.empty()) {
        return AddAppRule(rule);
    }
    else {
        return AddNetworkRule(rule);
    }
}

bool WfpBlocker::AddAppRule(const Rule& rule) {
    std::vector<FWPM_FILTER_CONDITION0> conditions;
    FWPM_FILTER_CONDITION0 condition = { 0 };

    // Условие для пути к приложению
    std::wstring widePath = std::wstring(rule.appPath.begin(), rule.appPath.end());
    FWP_BYTE_BLOB* appBlob = nullptr;
    if (FwpmGetAppIdFromFileName0(widePath.c_str(), &appBlob) == ERROR_SUCCESS) {
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = appBlob;
        conditions.push_back(condition);
    }

    // Добавляем фильтры на разных слоях
    std::vector<GUID> layers = {
        rule.direction == RuleDirection::Outbound ?
            FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        rule.direction == RuleDirection::Outbound ?
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_TRANSPORT_V4
    };

    bool success = true;
    for (const auto& layer : layers) {
        if (!CreateBasicFilter(layer, rule, conditions)) {
            success = false;
        }
    }

    if (appBlob) {
        FwpmFreeMemory0((void**)&appBlob);
    }

    return success;
}

bool WfpBlocker::AddNetworkRule(const Rule& rule) {
    std::vector<FWPM_FILTER_CONDITION0> conditions;
    FWPM_FILTER_CONDITION0 condition = { 0 };

    // Добавляем условие для протокола
    if (rule.protocol != Protocol::ANY) {
        condition = { 0 };
        condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT8;
        switch (rule.protocol) {
        case Protocol::TCP: condition.conditionValue.uint8 = IPPROTO_TCP; break;
        case Protocol::UDP: condition.conditionValue.uint8 = IPPROTO_UDP; break;
        case Protocol::ICMP: condition.conditionValue.uint8 = IPPROTO_ICMP; break;
        default: break;
        }
        conditions.push_back(condition);
    }

    // Добавляем условие для IP-адреса
    if (!rule.destIp.empty() && rule.destIp != "0.0.0.0") {
        condition = { 0 };
        condition.fieldKey = rule.direction == RuleDirection::Outbound ?
            FWPM_CONDITION_IP_REMOTE_ADDRESS : FWPM_CONDITION_IP_LOCAL_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT32;
        IN_ADDR addr;
        if (inet_pton(AF_INET, rule.destIp.c_str(), &addr) == 1) {
            condition.conditionValue.uint32 = addr.s_addr;
            conditions.push_back(condition);
        }
    }

    // Добавляем условие для порта
    if (rule.destPort != 0) {
        condition = { 0 };
        condition.fieldKey = rule.direction == RuleDirection::Outbound ?
            FWPM_CONDITION_IP_REMOTE_PORT : FWPM_CONDITION_IP_LOCAL_PORT;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT16;
        condition.conditionValue.uint16 = (UINT16)rule.destPort;
        conditions.push_back(condition);
    }

    // Добавляем фильтры на разных слоях
    std::vector<GUID> layers = {
        rule.direction == RuleDirection::Outbound ?
            FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        rule.direction == RuleDirection::Outbound ?
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_TRANSPORT_V4
    };

    bool success = true;
    for (const auto& layer : layers) {
        if (!CreateBasicFilter(layer, rule, conditions)) {
            success = false;
        }
    }

    return success;
}

bool WfpBlocker::CreateBasicFilter(const GUID& layerKey, const Rule& rule,
    const std::vector<FWPM_FILTER_CONDITION0>& conditions) {
    FWPM_FILTER0 filter = { 0 };
    filter.layerKey = layerKey;
    filter.displayData.name = const_cast<wchar_t*>(L"Windows Firewall Rule");
    filter.action.type = rule.action == RuleAction::BLOCK ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = (UINT32)conditions.size();
    filter.filterCondition = (FWPM_FILTER_CONDITION0*)conditions.data();

    UINT64 filterId = 0;
    DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        filterIds.push_back(filterId);
        return true;
    }
    return false;
}