#pragma once
#include <fstream>
#include <mutex>
#include "types.h"

class Logger {
public:
    static Logger& Instance();

    void Initialize(const std::string& logPath);
    void LogConnection(const LogEntry& entry);
    std::vector<LogEntry> GetRecentLogs(int count = 100);

private:
    Logger() = default;
    ~Logger();

    std::ofstream logFile;
    mutable std::mutex logMutex;
    std::string logPath;
};