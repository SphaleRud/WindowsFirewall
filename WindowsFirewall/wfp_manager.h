#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include <string>
#include "rule.h"

class WfpFilterManager {
public:
    WfpFilterManager();
    ~WfpFilterManager();

    bool Initialize();
    void RemoveAllRules();
    bool AddRule(const Rule& rule);
    bool ApplyRules(const std::vector<Rule>& rules);

private:
    HANDLE engineHandle;
    std::vector<UINT64> addedFilterIds;
    static UINT8 ProtocolToNumber(Protocol proto);

    static bool MakeAppIdBlob(const std::string& appPath, std::vector<uint8_t>& appIdBlob);
};