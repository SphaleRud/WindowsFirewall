#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include "rule.h"

#pragma comment(lib, "fwpuclnt.lib")

class WfpBlocker {
public:
    WfpBlocker();
    ~WfpBlocker();

    bool Initialize();
    bool ApplyRule(const Rule& rule);
    void RemoveAllRules();

private:
    HANDLE engineHandle;
    std::vector<UINT64> filterIds;

    bool AddAppRule(const Rule& rule);
    bool AddNetworkRule(const Rule& rule);
    bool CreateBasicFilter(const GUID& layerKey, const Rule& rule,
        const std::vector<FWPM_FILTER_CONDITION0>& conditions);
};