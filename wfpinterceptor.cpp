#include "wfpinterceptor.h"
#include <fwpmu.h>
#include <ws2tcpip.h>
#include <iostream>

#pragma comment(lib, "fwpuclnt.lib")

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

    // Подписка на ALE connect/accept events (TCP/UDP)
    FWPM_NET_EVENT_SUBSCRIPTION0 sub = {};
    sub.enumTemplate.netEventEnumType = FWPM_NET_EVENT_KEYWORD_ALE_AUTH_CONNECT
        | FWPM_NET_EVENT_KEYWORD_ALE_AUTH_RECV_ACCEPT;
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

// WFP вызывает этот callback в отдельном потоке!
void NTAPI WfpInterceptor::NetEventCallback(const FWPM_NET_EVENT2* netEvent, void* context) {
    if (!netEvent || !context) return;
    WfpInterceptor* self = reinterpret_cast<WfpInterceptor*>(context);

    if (netEvent->header.ipVersion != FWP_IP_VERSION_V4) return;

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

    // PID и имя процесса
    info.processId = netEvent->header.processId;
    info.processName = "Unknown";

    // Направление (ALE_AUTH_CONNECT - исходящее, ALE_AUTH_RECV_ACCEPT - входящее)
    if (netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP ||
        netEvent->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW) {
        // Для событий классификации:
        // ALE_AUTH_CONNECT → Outgoing, ALE_AUTH_RECV_ACCEPT → Incoming.
        if (netEvent->header.layerId == FWPM_LAYER_ALE_AUTH_CONNECT_V4) {
            info.direction = PacketDirection::Outgoing;
        }
        else {
            info.direction = PacketDirection::Incoming;
        }
    }

    // Время
    time_t now = time(nullptr);
    char buffer[32] = {};
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    info.time = buffer;

    info.size = 0; // WFP не сообщает размер

    // Передаём в основной callback (UI)
    std::lock_guard<std::mutex> lock(self->callbackMutex);
    if (self->packetCallback)
        self->packetCallback(info);
}