#include <winsock2.h>
#include "wfp_manager.h"
#include <iostream>
#include <initguid.h>
#include <fwpmu.h>
#include <ws2tcpip.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "string_utils.h"
#include "firewall_logger.h"

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
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::SERVICE_STARTED,
        "WFP Filter Manager initialization started"
    );
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

struct ResolvedIPs {
    bool success;
    std::vector<std::string> ipAddresses;
    std::string error;
};

ResolvedIPs ResolveDomain(const std::string& domain) {
    ResolvedIPs result;
    result.success = false;

    std::cout << "[DNS] Starting resolution for domain: " << domain << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        result.error = "Failed to initialize WinSock";
        std::cerr << "[DNS] " << result.error << std::endl;
        return result;
    }

    try {
        struct addrinfo hints = { 0 };
        struct addrinfo* addrs = nullptr;

        // Настраиваем поиск только IPv4 адресов
        hints.ai_family = AF_INET;        // Только IPv4
        hints.ai_socktype = SOCK_STREAM;  // TCP
        hints.ai_protocol = IPPROTO_TCP;  // TCP протокол
        hints.ai_flags = AI_CANONNAME;    // Получаем каноническое имя

        std::cout << "[DNS] Calling getaddrinfo for " << domain << std::endl;

        int status = getaddrinfo(domain.c_str(), nullptr, &hints, &addrs);
        if (status != 0) {
            char msgbuf[256];
            sprintf_s(msgbuf, "Failed to resolve domain. Error code: %d, WSAError: %d", 
                     status, WSAGetLastError());
            result.error = msgbuf;
            std::cerr << "[DNS] " << result.error << std::endl;
            WSACleanup();
            return result;
        }

        // Перебираем все найденные адреса
        for (struct addrinfo* addr = addrs; addr != nullptr; addr = addr->ai_next) {
            char ipstr[INET_ADDRSTRLEN];
            void* ptr = &((struct sockaddr_in*)addr->ai_addr)->sin_addr;
            
            // Преобразуем IP в строку
            if (inet_ntop(AF_INET, ptr, ipstr, sizeof(ipstr))) {
                std::string ip = ipstr;
                std::cout << "[DNS] Found IP: " << ip << std::endl;
                
                // Проверяем, не добавляли ли мы уже этот IP
                if (std::find(result.ipAddresses.begin(), result.ipAddresses.end(), ip) 
                    == result.ipAddresses.end()) {
                    result.ipAddresses.push_back(ip);
                }
            }
            
            // Выводим каноническое имя, если есть
            if (addr->ai_canonname) {
                std::cout << "[DNS] Canonical name: " << addr->ai_canonname << std::endl;
            }
        }

        freeaddrinfo(addrs);
        
        if (result.ipAddresses.empty()) {
            result.error = "No IPv4 addresses found";
            result.success = false;
            std::cerr << "[DNS] " << result.error << std::endl;
        } else {
            result.success = true;
            std::cout << "[DNS] Successfully resolved " << result.ipAddresses.size() 
                     << " unique IPv4 addresses" << std::endl;
        }
    }
    catch (const std::exception& e) {
        result.error = "Exception during DNS resolution: " + std::string(e.what());
        result.success = false;
        std::cerr << "[DNS] " << result.error << std::endl;
    }

    WSACleanup();
    return result;
}

void WfpFilterManager::RemoveAllRules() {
    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::SERVICE_STARTED,
        "Removing all WFP filters"
    );
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
    FirewallEvent event;
    event.type = FirewallEventType::RULE_ADDED;
    event.ruleName = rule.name;
    event.description = "WFP filter added";
    event.username = FirewallLogger::Instance().GetCurrentUsername();
    if (!engineHandle) {
        std::cerr << "[WFP] Engine handle is null" << std::endl;
        return false;
    }

    if (!rule.enabled && !isChildRule) {
        std::cout << "[WFP] Skipping disabled rule: " << rule.name << std::endl;
        return true;
    }

    std::cout << "\n[WFP] Adding new rule:" << std::endl
        << "Name: " << rule.name << std::endl
        << "Protocol: " << ProtocolToString(rule.protocol) << std::endl
        << "Direction: " << (rule.direction == RuleDirection::Inbound ? "Inbound" : "Outbound") << std::endl
        << "Action: " << (rule.action == RuleAction::BLOCK ? "Block" : "Allow") << std::endl
        << "Source IP/Domain: " << rule.sourceIp << std::endl
        << "Dest IP/Domain: " << rule.destIp << std::endl
        << "Source Port: " << (rule.sourcePortStr.empty() ? std::to_string(rule.sourcePort) : rule.sourcePortStr) << std::endl
        << "Dest Port: " << (rule.destPortStr.empty() ? std::to_string(rule.destPort) : rule.destPortStr) << std::endl
        << "App Path: " << rule.appPath << std::endl;

    // Специальная обработка для правил приложений
    if (!rule.appPath.empty()) {
        std::vector<uint8_t> appIdBlob;
        if (!MakeAppIdBlob(rule.appPath, appIdBlob)) {
            std::cerr << "[WFP] Failed to create app ID blob" << std::endl;
            return false;
        }

        const GUID* layers[] = {
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        };

        for (const GUID* layerKey : layers) {
            FWPM_FILTER0 filter = { 0 };
            FWPM_FILTER_CONDITION0 conditions[2] = { 0 };

            GUID filterKey;
            if (CoCreateGuid(&filterKey) == S_OK) {
                filter.filterKey = filterKey;
            }

            filter.layerKey = *layerKey;
            filter.displayData.name = const_cast<wchar_t*>(L"AppRule");
            filter.displayData.description = const_cast<wchar_t*>(L"Application filter rule");
            filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 15;
            filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

            conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
            conditions[0].matchType = FWP_MATCH_EQUAL;
            conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
            conditions[0].conditionValue.byteBlob = new FWP_BYTE_BLOB;
            conditions[0].conditionValue.byteBlob->size = (UINT32)appIdBlob.size();
            conditions[0].conditionValue.byteBlob->data = appIdBlob.data();

            filter.numFilterConditions = 1;
            filter.filterCondition = conditions;

            UINT64 filterId = 0;
            DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

            if (result == ERROR_SUCCESS) {
                addedFilterIds.push_back(filterId);
                std::cout << "[WFP] App filter added successfully, id: " << filterId << std::endl;
            }
            else {
                std::cerr << "[WFP] Failed to add app filter, error: " << result << std::endl;
            }

            delete conditions[0].conditionValue.byteBlob;
        }
        FirewallLogger::Instance().LogRuleEvent(event);
        return true;
    }

    // Резолвим IP-адреса из доменов
    std::vector<std::string> sourceIPs;
    std::vector<std::string> destIPs;

    if (!rule.sourceIp.empty() && rule.sourceIp != "0.0.0.0") {
        IN_ADDR addr = { 0 };
        if (InetPtonA(AF_INET, rule.sourceIp.c_str(), &addr) == 1) {
            sourceIPs.push_back(rule.sourceIp);
        }
        else {
            auto resolved = ResolveDomain(rule.sourceIp);
            if (resolved.success) {
                sourceIPs = resolved.ipAddresses;
                std::cout << "[WFP] Resolved source domain " << rule.sourceIp
                    << " to " << resolved.ipAddresses.size() << " IPs" << std::endl;
            }
            else {
                std::cerr << "[WFP] Failed to resolve source domain: " << resolved.error << std::endl;
                return false;
            }
        }
    }

    if (!rule.destIp.empty() && rule.destIp != "0.0.0.0") {
        IN_ADDR addr = { 0 };
        if (InetPtonA(AF_INET, rule.destIp.c_str(), &addr) == 1) {
            destIPs.push_back(rule.destIp);
        }
        else {
            auto resolved = ResolveDomain(rule.destIp);
            if (resolved.success) {
                destIPs = resolved.ipAddresses;
                std::cout << "[WFP] Resolved destination domain " << rule.destIp
                    << " to " << resolved.ipAddresses.size() << " IPs" << std::endl;
            }
            else {
                std::cerr << "[WFP] Failed to resolve domain: " << resolved.error << std::endl;
                return false;
            }
        }
    }

    // Создаем отдельное правило для каждого IP-адреса
    bool success = true;
    if (!destIPs.empty()) {
        for (const auto& destIP : destIPs) {
            FWPM_FILTER0 filter = { 0 };
            FWPM_FILTER_CONDITION0 conditions[3] = { 0 }; // Уменьшили максимальное количество условий
            UINT32 condCount = 0;

            // Создаем уникальный GUID для фильтра
            GUID filterKey;
            if (CoCreateGuid(&filterKey) == S_OK) {
                filter.filterKey = filterKey;
            }

            // Базовые параметры фильтра
            filter.displayData.name = const_cast<wchar_t*>(L"DomainRule");
            filter.displayData.description = const_cast<wchar_t*>(L"Domain filter rule");
            filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 15;

            // Настраиваем слой
            filter.layerKey = (rule.direction == RuleDirection::Inbound)
                ? FWPM_LAYER_INBOUND_TRANSPORT_V4
                : FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

            // Добавляем условие протокола
            if (rule.protocol != Protocol::ANY) {
                conditions[condCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT8;
                conditions[condCount].conditionValue.uint8 = ProtocolToNumber(rule.protocol);
                condCount++;
            }

            // Добавляем условие IP-адреса
            IN_ADDR addr = { 0 };
            if (InetPtonA(AF_INET, destIP.c_str(), &addr) == 1) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_LOCAL_ADDRESS
                    : FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT32;
                conditions[condCount].conditionValue.uint32 = addr.S_un.S_addr;
                condCount++;
            }

            // Добавляем условие порта, если указан
            if (!rule.destPortStr.empty()) {
                size_t rangePos = rule.destPortStr.find('-');
                if (rangePos != std::string::npos) {
                    UINT16 startPort = static_cast<UINT16>(std::stoi(rule.destPortStr.substr(0, rangePos)));
                    UINT16 endPort = static_cast<UINT16>(std::stoi(rule.destPortStr.substr(rangePos + 1)));

                    conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                        ? FWPM_CONDITION_IP_LOCAL_PORT
                        : FWPM_CONDITION_IP_REMOTE_PORT;
                    conditions[condCount].matchType = FWP_MATCH_RANGE;
                    conditions[condCount].conditionValue.type = FWP_RANGE_TYPE;
                    conditions[condCount].conditionValue.rangeValue = new FWP_RANGE0;
                    conditions[condCount].conditionValue.rangeValue->valueLow.type = FWP_UINT16;
                    conditions[condCount].conditionValue.rangeValue->valueLow.uint16 = startPort;
                    conditions[condCount].conditionValue.rangeValue->valueHigh.type = FWP_UINT16;
                    conditions[condCount].conditionValue.rangeValue->valueHigh.uint16 = endPort;
                    condCount++;
                }
            }
            else if (rule.destPort != 0) {
                conditions[condCount].fieldKey = (rule.direction == RuleDirection::Inbound)
                    ? FWPM_CONDITION_IP_LOCAL_PORT
                    : FWPM_CONDITION_IP_REMOTE_PORT;
                conditions[condCount].matchType = FWP_MATCH_EQUAL;
                conditions[condCount].conditionValue.type = FWP_UINT16;
                conditions[condCount].conditionValue.uint16 = static_cast<UINT16>(rule.destPort);
                condCount++;
            }

            // Устанавливаем условия и действие
            filter.numFilterConditions = condCount;
            filter.filterCondition = conditions;
            filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
            filter.providerKey = NULL;

            // Добавляем фильтр
            UINT64 filterId = 0;
            DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

            if (result == ERROR_SUCCESS) {
                addedFilterIds.push_back(filterId);
                std::cout << "[WFP] Filter added successfully for IP " << destIP << ", id: " << filterId << std::endl;
            }
            else {
                std::cerr << "[WFP] Failed to add filter for IP " << destIP << ", error: " << result << std::endl;
                success = false;
            }

            // Очищаем память для диапазона портов
            for (UINT32 i = 0; i < condCount; i++) {
                if (conditions[i].conditionValue.type == FWP_RANGE_TYPE) {
                    delete conditions[i].conditionValue.rangeValue;
                }
            }
        }
    }
    else {
        // Если нет IP-адресов, создаем одно правило
        FWPM_FILTER0 filter = { 0 };
        FWPM_FILTER_CONDITION0 conditions[2] = { 0 };
        UINT32 condCount = 0;

        GUID filterKey;
        if (CoCreateGuid(&filterKey) == S_OK) {
            filter.filterKey = filterKey;
        }

        filter.displayData.name = const_cast<wchar_t*>(L"GeneralRule");
        filter.displayData.description = const_cast<wchar_t*>(L"General filter rule");
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.layerKey = (rule.direction == RuleDirection::Inbound)
            ? FWPM_LAYER_INBOUND_TRANSPORT_V4
            : FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 15;

        if (rule.protocol != Protocol::ANY) {
            conditions[condCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[condCount].matchType = FWP_MATCH_EQUAL;
            conditions[condCount].conditionValue.type = FWP_UINT8;
            conditions[condCount].conditionValue.uint8 = ProtocolToNumber(rule.protocol);
            condCount++;
        }

        filter.numFilterConditions = condCount;
        filter.filterCondition = conditions;
        filter.action.type = (rule.action == RuleAction::BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

        UINT64 filterId = 0;
        DWORD result = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

        if (result == ERROR_SUCCESS) {
            addedFilterIds.push_back(filterId);
            std::cout << "[WFP] General filter added successfully, id: " << filterId << std::endl;
        }
        else {
            std::cerr << "[WFP] Failed to add general filter, error: " << result << std::endl;
            success = false;
        }
    }
    return true;
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