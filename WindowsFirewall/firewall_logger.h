#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <sstream>
#include <windows.h>
#include <filesystem>
#include <iostream>
#include "types.h"

enum class FirewallEventType {  
    RULE_ADDED,  
    RULE_MODIFIED,  
    RULE_DELETED,  
    RULE_ENABLED,  
    RULE_DISABLED,  
    CAPTURE_STARTED,  
    CAPTURE_STOPPED,  
    SERVICE_STARTED,  
    FIREWALL_SERVICE_STOPPED,
    SERVICE_ERROR,
    ADAPTER_CHANGED,
    FILTER_CHANGED,   
    PACKETS_CLEARED, 
    PACKETS_SAVED,
    SERVICE_EVENT
};  

// Структура события
struct FirewallEvent {
    FirewallEventType type;
    std::string ruleName;
    std::string description;
    std::string username;
    std::string previousValue;
    std::string newValue;
};



class FirewallLogger {
private:
    std::string logFilePath;
    std::ofstream logFile;
    std::mutex mutex;
    bool isInitialized = false;
    std::string baseFilename;

    FirewallLogger() = default;

public:
    static FirewallLogger& Instance() {
        static FirewallLogger instance;
        return instance;
    }

    FirewallLogger(const FirewallLogger&) = delete;
    FirewallLogger& operator=(const FirewallLogger&) = delete;

    bool Initialize(const std::string& filename = "firewall_events.log") {
        if (isInitialized) return true;

        std::lock_guard<std::mutex> lock(mutex);

        try {
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
                return false;
            }

            std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();
            std::filesystem::path logsDir = exeDir / "logs";

            try {
                if (!std::filesystem::exists(logsDir)) {
                    std::filesystem::create_directory(logsDir);
                }
            }
            catch (const std::filesystem::filesystem_error& e) {
                logsDir = std::filesystem::current_path();
            }

            // Создаем имя файла с текущей датой и временем
            time_t now = time(nullptr);
            struct tm timeinfo;
            localtime_s(&timeinfo, &now);
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &timeinfo);

            // Формируем имя файла: base_YYYYMMDD_HHMMSS.log
            baseFilename = filename.substr(0, filename.find_last_of('.'));
            std::string newFilename = baseFilename + "_" + timestamp + ".log";

            logFilePath = (logsDir / newFilename).string();

            logFile.open(logFilePath, std::ios::out); // Используем std::ios::out вместо app
            if (!logFile.is_open()) {
                return false;
            }

            // Записываем заголовок лога
            logFile << "=== Windows Firewall Log ===" << std::endl;
            logFile << "Started at: " << GetTimestamp() << std::endl;
            logFile << "User: " << GetCurrentUsername() << std::endl;
            logFile << "================================================" << std::endl << std::endl;
            logFile.flush();

            isInitialized = true;
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Error initializing logger: " << e.what() << std::endl;
            return false;
        }
    }

    void LogRuleEvent(const FirewallEvent& event) {
        if (!isInitialized) return;

        std::lock_guard<std::mutex> lock(mutex);
        try {
            if (logFile.is_open()) {
                std::string eventTypeStr = GetEventTypeString(event.type);
                std::stringstream logEntry;

                // Базовая информация о событии
                logEntry << "[" << GetTimestamp() << "] "
                    << "[" << eventTypeStr << "] "
                    << "User: " << event.username << "\n";

                // Подробная информация о правиле в зависимости от типа события
                switch (event.type) {
                case FirewallEventType::RULE_ADDED:
                    logEntry << "Added new rule:\n"
                        << FormatRuleDetails(event.ruleName, event.description, event.newValue);
                    break;

                case FirewallEventType::RULE_MODIFIED:
                    logEntry << "Modified rule: " << event.ruleName << "\n"
                        << "Previous state:\n"
                        << FormatRuleDetails("", "", event.previousValue)
                        << "New state:\n"
                        << FormatRuleDetails("", "", event.newValue);
                    break;

                case FirewallEventType::RULE_DELETED:
                    logEntry << "Deleted rule:\n"
                        << FormatRuleDetails(event.ruleName, event.description, event.previousValue);
                    break;

                case FirewallEventType::RULE_ENABLED:
                    logEntry << "Enabled rule:\n"
                        << FormatRuleDetails(event.ruleName, event.description, event.newValue);
                    break;

                case FirewallEventType::RULE_DISABLED:
                    logEntry << "Disabled rule:\n"
                        << FormatRuleDetails(event.ruleName, event.description, event.newValue);
                    break;

                default:
                    logEntry << event.description;
                }

                logFile << logEntry.str() << "\n----------------------------------------\n" << std::endl;
                logFile.flush();
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error writing to log: " << e.what() << std::endl;
        }
    }

    void LogServiceEvent(FirewallEventType type, const std::string& description) {
        if (!isInitialized) return;

        try {
            FirewallEvent event;
            event.type = type;
            event.description = description;
            event.username = GetCurrentUsername();
            LogRuleEvent(event);
        }
        catch (const std::exception& e) {
            std::cerr << "Error in LogServiceEvent: " << e.what() << std::endl;
        }
    }

    void LogPacket(const PacketInfo& packet) {
        if (!isInitialized) return;

        std::lock_guard<std::mutex> lock(mutex);
        try {
            if (logFile.is_open()) {
                logFile << "[" << GetTimestamp() << "] [PACKET] "
                    << packet.protocol << " "
                    << packet.sourceIp << ":" << packet.sourcePort << " -> "
                    << packet.destIp << ":" << packet.destPort << " "
                    << "[" << packet.processName << ":" << packet.processId << "] "
                    << FormatSize(packet.size);

                logFile << std::endl;
                logFile.flush();
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error writing packet to log: " << e.what() << std::endl;
        }
    }

    ~FirewallLogger() {
        try {
            std::lock_guard<std::mutex> lock(mutex);
            if (logFile.is_open()) {
                logFile << "\n=== Windows Firewall Log Ended at " << GetTimestamp() << " ===\n" << std::endl;
                logFile.close();
            }
        }
        catch (...) {
            // Игнорируем исключения в деструкторе
        }
    }
    std::string GetCurrentUsername() const {
        try {
            char username[256];
            DWORD username_len = 256;
            if (GetUserNameA(username, &username_len)) {
                return std::string(username);
            }
            return "UNKNOWN_USER";
        }
        catch (...) {
            return "UNKNOWN_USER";
        }
    }

private:
    std::string GetProtocolString(Protocol proto) const {
        switch (proto) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::ANY: return "ANY";
        default: return "UNKNOWN";
        }
    }
    std::string FormatSize(size_t bytes) const {
        if (bytes < 1024) return std::to_string(bytes) + "B";
        if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + "K";
        if (bytes < 1024 * 1024 * 1024) return std::to_string(bytes / (1024 * 1024)) + "M";
        return std::to_string(bytes / (1024 * 1024 * 1024)) + "G";
    }

    std::string FormatRuleDetails(const std::string& name, const std::string& description, const std::string& ruleData) const {
        std::stringstream ss;
        ss << "    Name: " << (name.empty() ? "(from data)" : name) << "\n"
            << "    Description: " << (description.empty() ? "(from data)" : description) << "\n"
            << "    Details:\n";

        // Разбираем JSON или форматированную строку с данными правила
        if (!ruleData.empty()) {
            std::istringstream dataStream(ruleData);
            std::string line;
            while (std::getline(dataStream, line)) {
                ss << "        " << line << "\n";
            }
        }

        return ss.str();
    }
    std::string GetTimestamp() const {
        try {
            time_t now = time(nullptr);
            struct tm timeinfo;
            char timestamp[64];
            localtime_s(&timeinfo, &now);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);
            return std::string(timestamp);
        }
        catch (...) {
            return "TIME_ERROR";
        }
    }
    std::string GetEventTypeString(FirewallEventType type) const {
        switch (type) {
        case FirewallEventType::RULE_ADDED: return "RULE_ADDED";
        case FirewallEventType::RULE_MODIFIED: return "RULE_MODIFIED";
        case FirewallEventType::RULE_DELETED: return "RULE_DELETED";
        case FirewallEventType::RULE_ENABLED: return "RULE_ENABLED";
        case FirewallEventType::RULE_DISABLED: return "RULE_DISABLED";
        case FirewallEventType::CAPTURE_STARTED: return "CAPTURE_STARTED";
        case FirewallEventType::CAPTURE_STOPPED: return "CAPTURE_STOPPED";
        case FirewallEventType::SERVICE_STARTED: return "SERVICE_STARTED";
        case FirewallEventType::FIREWALL_SERVICE_STOPPED: return "SERVICE_STOPPED";
        case FirewallEventType::SERVICE_ERROR: return "SERVICE_ERROR";
        case FirewallEventType::ADAPTER_CHANGED: return "ADAPTER_CHANGED";
        case FirewallEventType::FILTER_CHANGED: return "FILTER_CHANGED";
        case FirewallEventType::PACKETS_CLEARED: return "PACKETS_CLEARED";
        case FirewallEventType::PACKETS_SAVED: return "PACKETS_SAVED";
        case FirewallEventType::SERVICE_EVENT: return "SERVICE_EVENT";
        default: return "UNKNOWN";
        }
    }
};