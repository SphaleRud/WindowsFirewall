#include "wfpinterceptor.h"
#include <fwpmu.h>
#include <ws2tcpip.h>
#include <iostream>
#include <ctime>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

WfpInterceptor::WfpInterceptor()
    : engineHandle(nullptr), netEventSub(nullptr), isCapturing(false), stopEvent(nullptr) {
}

WfpInterceptor::~WfpInterceptor() {
    StopCapture();
    Shutdown();
}

bool WfpInterceptor::Initialize() {
    if (engineHandle) return true;
    DWORD result = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        &engineHandle
    );
    return (result == ERROR_SUCCESS);
}

void WfpInterceptor::Shutdown() {
    StopCapture();
    if (engineHandle) {
        FwpmEngineClose0(engineHandle);
        engineHandle = nullptr;
    }
}

void WfpInterceptor::SetPacketCallback(std::function<void(const PacketInfo&)> cb) {
    std::lock_guard<std::mutex> lock(callbackMutex);
    packetCallback = std::move(cb);
}

bool WfpInterceptor::StartCapture() {
    if (!engineHandle || isCapturing) return false;
    stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    FWPM_NET_EVENT_SUBSCRIPTION0 sub = {};
    sub.flags = 0;

    DWORD result = FwpmNetEventSubscribe0(
        engineHandle,
        &sub,
        (FWPM_NET_EVENT_CALLBACK0)NetEventCallback,
        this,
        &netEventSub
    );
    if (result != ERROR_SUCCESS) {
        CloseHandle(stopEvent);
        stopEvent = nullptr;
        return false;
    }
    isCapturing = true;
    eventThread = std::thread(EventThreadProc, this);
    return true;
}

void WfpInterceptor::StopCapture() {
    if (!isCapturing) return;
    isCapturing = false;
    if (stopEvent) {
        SetEvent(stopEvent);
    }
    if (eventThread.joinable())
        eventThread.join();

    if (engineHandle && netEventSub) {
        FwpmNetEventUnsubscribe0(engineHandle, netEventSub);
        netEventSub = nullptr;
    }
    if (stopEvent) {
        CloseHandle(stopEvent);
        stopEvent = nullptr;
    }
}

void WfpInterceptor::EventThreadProc(WfpInterceptor* interceptor) {
    HANDLE hStop = interceptor->stopEvent;
    while (WaitForSingleObject(hStop, 1000) == WAIT_TIMEOUT) {
        // просто держим поток живым
    }
}

// Только *_0 структуры, processId нет, direction по layerId
void NTAPI WfpInterceptor::NetEventCallback(const FWPM_NET_EVENT2* netEvent, void* context) {
    OutputDebugStringA("!!! NetEventCallback called\n");
    if (!netEvent) return;

    char buf[256];
    sprintf(buf, "type=%u\n", netEvent->type);
    OutputDebugStringA(buf);

    // Обрабатываем только ALE события
    if (netEvent->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW && netEvent->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        OutputDebugStringA("Not ALE event, skipping\n");
        return;
    }

    // Здесь уже можно безопасно работать с netEvent->header
    sprintf(buf, "ipVersion=%u, proto=%u\n", netEvent->header.ipVersion, netEvent->header.ipProtocol);
    OutputDebugStringA(buf);

 //   if (!netEvent || !context) return;
    WfpInterceptor* self = reinterpret_cast<WfpInterceptor*>(context);

 //   if (netEvent->header.ipVersion != FWP_IP_VERSION_V4)
 //       return;

    PacketInfo info;

    // IP адреса
    char srcIpStr[INET_ADDRSTRLEN] = {};
    char dstIpStr[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &netEvent->header.localAddrV4, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &netEvent->header.remoteAddrV4, dstIpStr, INET_ADDRSTRLEN);

    info.sourceIp = srcIpStr;
    info.destIp = dstIpStr;

    // Порты
    info.sourcePort = ntohs(netEvent->header.localPort);
    info.destPort = ntohs(netEvent->header.remotePort);

    // Протокол
    switch (netEvent->header.ipProtocol) {
    case IPPROTO_TCP: info.protocol = "TCP"; break;
    case IPPROTO_UDP: info.protocol = "UDP"; break;
    case IPPROTO_ICMP: info.protocol = "ICMP"; break;
    default: info.protocol = "OTHER"; break;
    }

    info.direction = PacketDirection::Incoming;
    info.processId = 0; // processId не поддерживается в *_0

    constexpr UINT16 ALE_AUTH_CONNECT_V4_ID = 44;
    constexpr UINT16 ALE_AUTH_RECV_ACCEPT_V4_ID = 46;

    if (netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW && netEvent->classifyAllow) {
        sprintf(buf, "classifyAllow layerId=%u\n", netEvent->classifyAllow->layerId);
        OutputDebugStringA(buf);
    }
    if (netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP && netEvent->classifyDrop) {
        sprintf(buf, "classifyDrop layerId=%u\n", netEvent->classifyDrop->layerId);
        OutputDebugStringA(buf);
    }

    // ALE события: разрешённые
    if (netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) {
        const FWPM_NET_EVENT_CLASSIFY_ALLOW0* allow = netEvent->classifyAllow;
        if (allow) {
            if (allow->layerId == ALE_AUTH_CONNECT_V4_ID)
                info.direction = PacketDirection::Outgoing;
            else if (allow->layerId == ALE_AUTH_RECV_ACCEPT_V4_ID)
                info.direction = PacketDirection::Incoming;
        }
    }
    // ALE события: заблокированные
    else if (netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        const FWPM_NET_EVENT_CLASSIFY_DROP2* drop = netEvent->classifyDrop;
        if (drop) {
            if (drop->layerId == ALE_AUTH_CONNECT_V4_ID)
                info.direction = PacketDirection::Outgoing;
            else if (drop->layerId == ALE_AUTH_RECV_ACCEPT_V4_ID)
                info.direction = PacketDirection::Incoming;
        }
    }

    // Время
    time_t now = time(nullptr);
    char buffer[32] = {};
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    info.time = buffer;


    sprintf(buf, "WFP Packet: src=%s dst=%s proto=%s dir=%d\n",
        info.sourceIp.c_str(), info.destIp.c_str(), info.protocol.c_str(), (int)info.direction);
    OutputDebugStringA(buf);

    // Передаём в основной callback (UI)
    std::lock_guard<std::mutex> lock(self->callbackMutex);
    if (self->packetCallback)
        OutputDebugStringA("!!! WFP: packetCallback will be called\n");
        self->packetCallback(info);
}