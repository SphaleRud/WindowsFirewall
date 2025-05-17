#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <memory>
#include "packetinterceptor.h"
#include <queue>
#include <mutex>
#include "types.h"
#include "resource.h"

class MainWindow {
public:
    static MainWindow& Instance();
    bool Initialize(HINSTANCE hInstance, int nCmdShow);
    void Show();
    void SetPacketInterceptor(std::shared_ptr<PacketInterceptor> interceptor);

private:
    MainWindow();
    ~MainWindow();
    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HWND hwnd;
    HINSTANCE hInstance;
    HWND rulesListView;
    bool isCapturing;
    HWND connectionsListView;
    std::shared_ptr<PacketInterceptor> packetInterceptor;

    // Добавляем очередь пакетов и мьютекс
    std::queue<PacketInfo> packetQueue;
    std::mutex packetMutex;
    static const UINT WM_UPDATE_PACKET = WM_USER + 1;

    void ShowAdapterSelectionDialog();
    std::string selectedAdapterIp;

    void InitializeRulesList();
    void InitializeConnectionsList();
    void AddRule();
    void DeleteRule();
    void UpdateRulesList();        // Добавлено
    void UpdateConnectionsList();   // Добавлено
    void StartCapture();
    void StopCapture();
    void AddPacketToList(const PacketInfo& info);
    void OnPacketReceived(const PacketInfo& info);
};