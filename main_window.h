#pragma once
#include <Windows.h>
#include <CommCtrl.h>
#include <memory>
#include <queue>
#include <mutex>
#include "packetinterceptor.h"
#include "resource.h"
#include "connection_tracker.h"

#define WM_UPDATE_PACKET (WM_USER + 1)

// Добавляем структуру AdapterData
struct AdapterData {
    std::wstring name;
    std::string ipAddress;
};


class MainWindow {
public:
    static MainWindow& Instance(HINSTANCE hInst = nullptr) {
        static MainWindow instance(hInst);
        return instance;
    }

    bool Initialize();
    void Show(int nCmdShow);
    HWND GetHWND() const { return hwnd; }
    bool Create();
    void InitializeRulesList();
    void InitializeConnectionsList();
    void UpdateRulesList();
    void UpdateConnectionsList();
    void StartCapture();
    void StopCapture();
    void AddRule();
    void DeleteRule();
    void AddPacketToList(const PacketInfo& info);
    void OnPacketReceived(const PacketInfo& info);
    void SetPacketInterceptor(std::shared_ptr<PacketInterceptor> interceptor);

private:
    explicit MainWindow(HINSTANCE hInst);
    ~MainWindow();
    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK AdapterDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    bool RegisterWindowClass();
    void CreateToolbar();
    void UpdateLayout();   
    ConnectionTracker connectionTracker;

    HWND hwnd;
    HINSTANCE hInstance;
    HWND rulesListView;
    HWND connectionsListView;
    HWND toolBar;       
    std::shared_ptr<PacketInterceptor> packetInterceptor;
    std::queue<PacketInfo> packetQueue;
    std::mutex packetMutex;
    bool isCapturing;

    void LogError(const wchar_t* message);
    void ShowErrorMessage(const wchar_t* message);
};