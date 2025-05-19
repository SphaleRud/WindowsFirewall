#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include "types.h"

class WfpInterceptor {
public:
    WfpInterceptor();
    ~WfpInterceptor();

    bool Initialize();
    void Shutdown();

    bool StartCapture();
    void StopCapture();
    bool IsCapturing() const { return isCapturing; }

    void SetPacketCallback(std::function<void(const PacketInfo&)> cb);

private:
    HANDLE engineHandle;
    HANDLE netEventSub;
    std::function<void(const PacketInfo&)> packetCallback;
    std::mutex callbackMutex;
    std::thread eventThread;
    bool isCapturing;
    HANDLE stopEvent;

    static void EventThreadProc(WfpInterceptor* interceptor);
    static void NTAPI NetEventCallback(const FWPM_NET_EVENT2* netEvent, void* context);
};