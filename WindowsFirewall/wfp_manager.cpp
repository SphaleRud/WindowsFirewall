#include <winsock2.h>
#include "wfp_manager.h"
#include <iostream>
#include <initguid.h>
#include <fwpmu.h>
#include <ws2tcpip.h>
#pragma comment(lib, "fwpuclnt.lib")

WfpFilterManager::WfpFilterManager() : engineHandle(nullptr) {}

WfpFilterManager::~WfpFilterManager() {
    RemoveAllRules();
    if (engineHandle) {
        FwpmEngineClose(engineHandle);
    }
}

bool WfpFilterManager::Initialize() {
    if (FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle) != ERROR_SUCCESS) {
        std::cerr << "Failed to open WFP engine" << std::endl;
        engineHandle = nullptr;
        return false;
    }
    return true;
}

void WfpFilterManager::RemoveAllRules() {
    if (!engineHandle) return;
    for (UINT64 id : addedFilterIds) {
        FwpmFilterDeleteById(engineHandle, id);
    }
    addedFilterIds.clear();
}

UINT8 WfpFilterManager::ProtocolToNumber(Protocol proto) {
    switch (proto) {
    case Protocol::TCP: return 6;
    case Protocol::UDP: return 17;
    case Protocol::ICMP: return 1;
    default: return 0; // ANY
    }
}

// Перевод std::string (UTF-8) в std::vector<uint8_t> с WCHAR-ами
bool WfpFilterManager::MakeAppIdBlob(const std::string& appPath, std::vector<uint8_t>& appIdBlob) {
    // Сначала считаем длину
    int wlen = MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::vector<wchar_t> wideBuf(wlen);
    MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, wideBuf.data(), wlen);

    // Преобразуем в байтовый массив для BLOB
    size_t size = wlen * sizeof(wchar_t);
    appIdBlob.resize(size);
    memcpy(appIdBlob.data(), wideBuf.data(), size);
    return true;
}

bool WfpFilterManager::AddRule(const Rule& rule) {
    if (!engineHandle) return false;

    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION cond[6];
    int condCount = 0;

    filter.displayData.name = (wchar_t*)L"WindowsFirewallRule";
    filter.layerKey = (rule.direction == RuleDirection::Inbound)
        ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_EMPTY;

    // Протокол
    if (rule.protocol != Protocol::ANY) {
        cond[condCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_UINT8;
        cond[condCount].conditionValue.uint8 = ProtocolToNumber(rule.protocol);
        condCount++;
    }
    // Source IP
    if (!rule.sourceIp.empty()) {
        cond[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
            ? FWPM_CONDITION_IP_REMOTE_ADDRESS
            : FWPM_CONDITION_IP_LOCAL_ADDRESS;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_UINT32;
        IN_ADDR addr = {};
        if (InetPtonA(AF_INET, rule.sourceIp.c_str(), &addr) == 1) {
            cond[condCount].conditionValue.uint32 = addr.S_un.S_addr;
            condCount++;
        }
    }
    // Dest IP
    if (!rule.destIp.empty()) {
        cond[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
            ? FWPM_CONDITION_IP_LOCAL_ADDRESS
            : FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_UINT32;
        IN_ADDR addr = {};
        if (InetPtonA(AF_INET, rule.destIp.c_str(), &addr) == 1) {
            cond[condCount].conditionValue.uint32 = addr.S_un.S_addr;
            condCount++;
        }
    }
    // Source port
    if (rule.sourcePort != 0) {
        cond[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
            ? FWPM_CONDITION_IP_REMOTE_PORT
            : FWPM_CONDITION_IP_LOCAL_PORT;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_UINT16;
        cond[condCount].conditionValue.uint16 = static_cast<UINT16>(rule.sourcePort);
        condCount++;
    }
    // Dest port
    if (rule.destPort != 0) {
        cond[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
            ? FWPM_CONDITION_IP_LOCAL_PORT
            : FWPM_CONDITION_IP_REMOTE_PORT;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_UINT16;
        cond[condCount].conditionValue.uint16 = static_cast<UINT16>(rule.destPort);
        condCount++;
    }
    // --- Фильтрация по appPath ---
    std::vector<uint8_t> appIdBlob;
    if (!rule.appPath.empty() && MakeAppIdBlob(rule.appPath, appIdBlob)) {
        // BLOB должен жить до удаления фильтра!
        static std::vector<std::vector<uint8_t>> persistentBlobs;
        persistentBlobs.push_back(appIdBlob);

        cond[condCount].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond[condCount].matchType = FWP_MATCH_EQUAL;
        cond[condCount].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        cond[condCount].conditionValue.byteBlob = new FWP_BYTE_BLOB;
        cond[condCount].conditionValue.byteBlob->size = (UINT32)appIdBlob.size();
        cond[condCount].conditionValue.byteBlob->data = persistentBlobs.back().data();
        condCount++;
    }

    filter.numFilterConditions = condCount;
    filter.filterCondition = cond;

    UINT64 filterId = 0;
    if (FwpmFilterAdd(engineHandle, &filter, NULL, &filterId) == ERROR_SUCCESS) {
        addedFilterIds.push_back(filterId);
        return true;
    }
    return false;
}

bool WfpFilterManager::ApplyRules(const std::vector<Rule>& rules) {
    RemoveAllRules();
    for (const auto& rule : rules) {
        if (rule.enabled) {
            AddRule(rule);
        }
    }
    return true;
}