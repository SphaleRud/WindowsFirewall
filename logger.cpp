#define _CRT_SECURE_NO_WARNINGS  // ����� �������� ��� ����������� ��� ������������ ���������� ������

#include "logger.h"
#include <fstream>
#include <ctime>
#include <iomanip>

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

void Logger::Initialize(const std::string& logPath) {
    std::lock_guard<std::mutex> lock(logMutex);
    this->logPath = logPath;
    logFile.open(logPath, std::ios::app);
}

void Logger::LogConnection(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (!logFile.is_open()) {
        return;
    }

    // ����������� ����� ��������� ���������� ������
    std::time_t t = entry.timestamp;
    std::tm tm;
    localtime_s(&tm, &t);  // ���������� ���������� ������

    logFile << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " | "
        << entry.sourceIp << ":" << entry.sourcePort << " -> "
        << entry.destIp << ":" << entry.destPort << " | "
        << "Protocol: " << static_cast<int>(entry.protocol) << " | "
        << "Action: " << (entry.action == RuleAction::ALLOW ? "ALLOW" : "BLOCK") << " | "
        << "Rule ID: " << entry.ruleId << std::endl;
}

std::vector<LogEntry> Logger::GetRecentLogs(int count) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::vector<LogEntry> logs;
    // ����� ����� �������� ������ ��������� ������� �� �����
    return logs;
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}