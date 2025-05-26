#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <ctime>
#include <sstream>

class Logger {
public:
    static Logger& Instance() {
        static Logger instance;
        return instance;
    }

    void Initialize(const std::string& filename) {
        std::lock_guard<std::mutex> lock(mutex);
        logFile.open(filename, std::ios::app);
    }

    void Log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex);
        if (logFile.is_open()) {
            logFile << GetTimestamp() << " - " << message << std::endl;
            logFile.flush();
        }
    }

private:
    Logger() {}
    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    std::string GetTimestamp() {
        time_t now = time(nullptr);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);
        return timestamp;
    }

    std::ofstream logFile;
    std::mutex mutex;
};