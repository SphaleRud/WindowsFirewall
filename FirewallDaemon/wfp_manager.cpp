#include <winsock2.h>
#include "wfp_manager.h"
#include <iostream>
#include <initguid.h>
#include <fwpmu.h>
#include <ws2tcpip.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")

WfpFilterManager::WfpFilterManager() : engineHandle(nullptr) {}

WfpFilterManager::~WfpFilterManager() {
    RemoveAllRules();
    if (engineHandle) {
        FwpmEngineClose(engineHandle);
    }
}

bool WfpFilterManager::Initialize() {
    FWPM_SESSION session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD result = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (result != ERROR_SUCCESS) {
        std::cerr << "[WFP] Failed to open WFP engine. Error code: " << result << std::endl;
        engineHandle = nullptr;
        return false;
    }

    std::cout << "[WFP] Engine initialized successfully" << std::endl;
    return true;
}


void WfpFilterManager::RemoveAllRules() {
    if (!engineHandle) return;

    std::cout << "[WFP] Removing all rules..." << std::endl;

    // Начинаем транзакцию для удаления
    if (FwpmTransactionBegin(engineHandle, 0) != ERROR_SUCCESS) {
        std::cerr << "[WFP] Failed to begin transaction for removal" << std::endl;
        return;
    }

    for (UINT64 id : addedFilterIds) {
        DWORD res = FwpmFilterDeleteById(engineHandle, id);
        if (res == ERROR_SUCCESS) {
            std::cout << "[WFP] Filter removed, id: " << id << std::endl;
        }
        else {
            std::cerr << "[WFP] Filter remove FAILED, id: " << id << " code: " << res << std::endl;
        }
    }

    if (FwpmTransactionCommit(engineHandle) != ERROR_SUCCESS) {
        std::cerr << "[WFP] Failed to commit removal transaction" << std::endl;
        FwpmTransactionAbort(engineHandle);
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

std::string WfpFilterManager::ProtocolToString(Protocol proto) {
    switch (proto) {
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP";
    default: return "ANY";
    }
}
bool WfpFilterManager::MakeAppIdBlob(const std::string& appPath, std::vector<uint8_t>& blob) {
    if (appPath.empty()) {
        return false;
    }

    // Конвертируем путь в широкие символы
    std::wstring widePath;
    int requiredSize = MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, nullptr, 0);
    if (requiredSize > 0) {
        widePath.resize(requiredSize);
        MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, &widePath[0], requiredSize);
    }

    // Нормализуем путь (заменяем обратные слеши на прямые)
    std::replace(widePath.begin(), widePath.end(), L'\\', L'/');

    // Объявляем указатель на FWP_BYTE_BLOB
    FWP_BYTE_BLOB* appIdBlob = nullptr;

    // Получаем AppId
    DWORD result = FwpmGetAppIdFromFileName0(widePath.c_str(), &appIdBlob);

    if (result != ERROR_SUCCESS) {
        std::cerr << "[WFP] Failed to get AppId, error: " << result << std::endl;
        return false;
    }

    if (appIdBlob != nullptr) {
        // Копируем данные в вектор
        blob.assign(appIdBlob->data, appIdBlob->data + appIdBlob->size);

        // Освобождаем память
        FwpmFreeMemory0((void**)&appIdBlob);

        std::cout << "[WFP] Successfully created AppId blob for: " << appPath
            << " (size: " << blob.size() << " bytes)" << std::endl;
        return true;
    }

    std::cerr << "[WFP] AppId blob is null" << std::endl;
    return false;
}

bool WfpFilterManager::AddRule(const Rule& rule, bool isChildRule = false) {
    if (!engineHandle) {
        std::cerr << "[WFP] Engine handle is null" << std::endl;
        return false;
    }

    // Проверяем, включено ли правило
    if (!rule.enabled && !isChildRule) {
        std::cout << "[WFP] Skipping disabled rule: " << rule.name << std::endl;
        return true;  // Возвращаем true, так как это не ошибка
    }

    std::cout << "\n[WFP] Adding new rule:" << std::endl
        << "Protocol: " << ProtocolToString(rule.protocol) << std::endl
        << "Direction: " << (rule.direction == RuleDirection::Inbound ? "Inbound" : "Outbound") << std::endl
        << "Action: " << (rule.action == RuleAction::BLOCK ? "Block" : "Allow") << std::endl
        << "Source IP: " << rule.sourceIp << std::endl
        << "Dest IP: " << rule.destIp << std::endl
        << "Source Port: " << rule.sourcePort << std::endl
        << "Dest Port: " << rule.destPort << std::endl
        << "App Path: " << rule.appPath << std::endl;

    // Специальная обработка для правил приложений
    if (!rule.appPath.empty()) {
        std::vector<uint8_t> appIdBlob;
        if (!MakeAppIdBlob(rule.appPath, appIdBlob)) {
            std::cerr << "[WFP] Failed to create app ID blob" << std::endl;
            return false;
        }

        // Массив слоев для фильтрации приложений
        const GUID* layers[] = {
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,      // Исходящие IPv4
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,  // Входящие IPv4
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6,      // Исходящие IPv6
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6   // Входящие IPv6
        };

        bool success = true;
        for (const GUID* layerKey : layers) {
            FWPM_FILTER0 filter = { 0 };
            FWPM_FILTER_CONDITION0 conditions[2] = { 0 };
            UINT32 condCount = 0;

            // Создаем уникальный GUID для фильтра
            GUID filterKey;
            if (CoCreateGuid(&filterKey) == S_OK) {
                filter.filterKey = filterKey;
            }

            // Базовые параметры фильтра
            filter.layerKey = *layerKey;
            filter.displayData.name = const_cast<wchar_t*>(L"AppBlockRule");
            filter.displayData.description = const_cast<wchar_t*>(L"Block network access for specific application");
            filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 0xF;  // Максимальный приоритет
            filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

            // Условие для идентификации приложения
            conditions[condCount].fieldKey = FWPM_CONDITION_ALE_APP_ID;
            conditions[condCount].matchType = FWP_MATCH_EQUAL;
            conditions[condCount].conditionValue.type = FWP_BYTE_BLOB_TYPE;
            conditions[condCount].conditionValue.byteBlob = new FWP_BYTE_BLOB;
            conditions[condCount].conditionValue.byteBlob->size = (UINT32)appIdBlob.size();
            conditions[condCount].conditionValue.byteBlob->data = appIdBlob.data();
            condCount++;

            filter.numFilterConditions = condCount;
            filter.filterCondition = conditions;
            filter.providerKey = NULL;

            // Добавляем фильтр
            UINT64 filterId = 0;
            DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

            if (result == ERROR_SUCCESS) {
                addedFilterIds.push_back(filterId);
                std::cout << "[WFP] App filter added successfully for layer "
                    << (layerKey == &FWPM_LAYER_ALE_AUTH_CONNECT_V4 ? "CONNECT_V4" :
                        layerKey == &FWPM_LAYER_ALE_AUTH_CONNECT_V6 ? "CONNECT_V6" :
                        layerKey == &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ? "ACCEPT_V4" :
                        "ACCEPT_V6")
                    << ", id: " << filterId << std::endl;

                // Проверяем статус фильтра
                FWPM_FILTER0* addedFilter = nullptr;
                if (FwpmFilterGetById0(engineHandle, filterId, &addedFilter) == ERROR_SUCCESS) {
                    std::cout << "[WFP] Filter verified, status: active" << std::endl;
                    FwpmFreeMemory((void**)&addedFilter);
                }
            }
            else {
                std::cerr << "[WFP] Failed to add app filter, error code: " << result << std::endl;
                success = false;
            }

            delete conditions[0].conditionValue.byteBlob;
        }

        return success;
    }
    else {
        // Если указан порт и протокол ANY, создаем правила для TCP и UDP
        if ((rule.sourcePort != 0 || rule.destPort != 0) && rule.protocol == Protocol::ANY && !isChildRule) {
            std::cout << "[WFP] Protocol is ANY and port is specified, creating TCP and UDP rules..." << std::endl;

            // Создаем правило для TCP
            Rule tcpRule = rule;
            tcpRule.protocol = Protocol::TCP;
            std::cout << "[WFP] Creating TCP rule for port "
                << (rule.destPort != 0 ? rule.destPort : rule.sourcePort) << std::endl;
            if (!AddRule(tcpRule, true)) {
                std::cerr << "[WFP] Failed to add TCP rule" << std::endl;
                return false;
            }

            // Создаем правило для UDP
            Rule udpRule = rule;
            udpRule.protocol = Protocol::UDP;
            std::cout << "[WFP] Creating UDP rule for port "
                << (rule.destPort != 0 ? rule.destPort : rule.sourcePort) << std::endl;
            if (!AddRule(udpRule, true)) {
                std::cerr << "[WFP] Failed to add UDP rule" << std::endl;
                return false;
            }

            std::cout << "[WFP] Successfully created both TCP and UDP rules" << std::endl;
            return true;
        }

        FWPM_FILTER0 filter = { 0 };
        FWPM_FILTER_CONDITION0 conditions[6] = { 0 };
        UINT32 condCount = 0;

        // Создаем уникальный GUID для фильтра
        GUID filterKey;
        if (CoCreateGuid(&filterKey) == S_OK) {
            filter.filterKey = filterKey;
        }

        // Базовые параметры фильтра
        filter.displayData.name = const_cast<wchar_t*>(L"PortRule");
        filter.displayData.description = const_cast<wchar_t*>(L"Custom port filter rule");
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;

        // Выбираем правильный слой для TCP/UDP/ICMP
        if (rule.protocol == Protocol::ICMP) {
            filter.layerKey = (rule.direction == RuleDirection::Inbound)
                ? FWPM_LAYER_INBOUND_TRANSPORT_V4
                : FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

            // Условие протокола для ICMP
            conditions[condCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[condCount].matchType = FWP_MATCH_EQUAL;
            conditions[condCount].conditionValue.type = FWP_UINT8;
            conditions[condCount].conditionValue.uint8 = IPPROTO_ICMP;
            condCount++;
        }
        else if (rule.protocol == Protocol::TCP || rule.protocol == Protocol::UDP) {
            // Для TCP/UDP используем транспортный слой
            filter.layerKey = (rule.direction == RuleDirection::Inbound)
                ? FWPM_LAYER_INBOUND_TRANSPORT_V4
                : FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

            // Добавляем условие протокола
            conditions[condCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[condCount].matchType = FWP_MATCH_EQUAL;
            conditions[condCount].conditionValue.type = FWP_UINT8;
            conditions[condCount].conditionValue.uint8 = ProtocolToNumber(rule.protocol);
            condCount++;
            std::cout << "[WFP] Adding protocol condition: " << ProtocolToString(rule.protocol) << std::endl;

            // Добавляем порты только для TCP/UDP
            if (rule.sourcePort != 0) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_REMOTE_PORT
                    : FWPM_CONDITION_IP_LOCAL_PORT;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT16;
                conditions[condCount].conditionValue.uint16 = static_cast<UINT16>(rule.sourcePort);
                condCount++;
                std::cout << "[WFP] Adding source port condition: " << rule.sourcePort << std::endl;
            }

            if (rule.destPort != 0) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_LOCAL_PORT
                    : FWPM_CONDITION_IP_REMOTE_PORT;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT16;
                conditions[condCount].conditionValue.uint16 = static_cast<UINT16>(rule.destPort);
                condCount++;
                std::cout << "[WFP] Adding destination port condition: " << rule.destPort << std::endl;
            }
        }

        // Добавляем условия IP-адресов
        if (!rule.sourceIp.empty() && rule.sourceIp != "0.0.0.0") {
            IN_ADDR addr = { 0 };
            if (InetPtonA(AF_INET, rule.sourceIp.c_str(), &addr) == 1) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_REMOTE_ADDRESS
                    : FWPM_CONDITION_IP_LOCAL_ADDRESS;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT32;
                conditions[condCount].conditionValue.uint32 = addr.S_un.S_addr;
                condCount++;
                std::cout << "[WFP] Adding source IP condition: " << rule.sourceIp << std::endl;
            }
        }

        if (!rule.destIp.empty() && rule.destIp != "0.0.0.0") {
            IN_ADDR addr = { 0 };
            if (InetPtonA(AF_INET, rule.destIp.c_str(), &addr) == 1) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_LOCAL_ADDRESS
                    : FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT32;
                conditions[condCount].conditionValue.uint32 = addr.S_un.S_addr;
                condCount++;
                std::cout << "[WFP] Adding destination IP condition: " << rule.destIp << std::endl;
            }
        }

        // Устанавливаем окончательные параметры фильтра
        filter.numFilterConditions = condCount;
        filter.filterCondition = conditions;
        filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
        filter.providerKey = NULL;

        // Проверяем, что у нас есть хотя бы одно условие
        if (condCount == 0) {
            std::cerr << "[WFP] Warning: No conditions specified for the filter" << std::endl;
            return false;
        }

        // Добавляем фильтр
        UINT64 filterId = 0;
        DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

        if (result == ERROR_SUCCESS) {
            addedFilterIds.push_back(filterId);
            std::cout << "[WFP] Filter added successfully, id: " << filterId << std::endl;

            // Проверяем статус фильтра
            FWPM_FILTER0* addedFilter = nullptr;
            if (FwpmFilterGetById0(engineHandle, filterId, &addedFilter) == ERROR_SUCCESS) {
                std::cout << "[WFP] Filter verified, status: active" << std::endl;
                FwpmFreeMemory((void**)&addedFilter);
                return true;
            }
        }
        else {
            std::cerr << "[WFP] Failed to add filter, error code: " << result << std::endl;
        }

        return false;
    }
}

bool WfpFilterManager::ApplyRules(const std::vector<Rule>& rules) {
    if (!engineHandle) {
        std::cerr << "[WFP] Cannot apply rules - engine not initialized" << std::endl;
        return false;
    }

    // Проверяем права доступа
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::cerr << "[WFP] Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    BOOL isElevated = FALSE;
    TOKEN_ELEVATION elevation;
    DWORD size;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        isElevated = elevation.TokenIsElevated;
    }
    CloseHandle(token);

    if (!isElevated) {
        std::cerr << "[WFP] Process needs to run with elevated privileges" << std::endl;
        return false;
    }

    std::cout << "[WFP] Applying " << rules.size() << " rules..." << std::endl;

    // Сначала удаляем старые правила без транзакции
    RemoveAllRules();

    bool success = true;
    for (const auto& rule : rules) {
        if (rule.enabled) {
            if (!AddRule(rule)) {
                std::cerr << "[WFP] Failed to add rule" << std::endl;
                success = false;
                break;
            }
        }
    }

    if (success) {
        std::cout << "[WFP] Rules applied successfully" << std::endl;
    }
    else {
        std::cerr << "[WFP] Failed to apply all rules" << std::endl;
        // Очищаем все правила в случае ошибки
        RemoveAllRules();
    }

    return success;
}