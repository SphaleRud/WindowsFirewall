#pragma once
#include <Windows.h>
#include <memory>
#include <queue>
#include <mutex>
#include "packetinterceptor.h"
#include "listview.h"
#include "resource.h"

// Определяем пользовательское сообщение
#define WM_UPDATE_PACKET (WM_USER + 1)

// Forward declarations

class MainWindow {
public:
    enum ControlIds {
        ID_START_CAPTURE = 1003,
        ID_STOP_CAPTURE = 1004,
        ID_ADD_RULE = 1005,
        ID_DELETE_RULE = 1006
    };

    MainWindow();
    ~MainWindow();

    void UpdateAdapterInfo(const std::string& adapterInfo);
    void UpdateAdapterInfo() { UpdateAdapterInfo("None"); }

    bool Initialize(HINSTANCE hInstance);
    void Show(int nCmdShow);

protected:
    void OnStartCapture();
    void OnSelectAdapter();
    bool CreateControls();
    void ShowAdapterSelectionDialog();
    LRESULT HandleCommand(WPARAM wParam, LPARAM lParam);
    LRESULT HandlePacketUpdate(WPARAM wParam, LPARAM lParam);

private:
    static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK AdapterDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
    static std::wstring StringToWString(const std::string& str);
    static std::string WStringToString(const std::wstring& wstr);
    static const int IDC_ADAPTER_LABEL = 1001;
    static const int IDC_SELECT_ADAPTER = 1002;
    static const int IDC_START_CAPTURE = 1003;
    static const int IDC_PACKET_LIST = 1004;

    bool CreateMainWindow();
    void StartCapture();
    void StopCapture();
    std::wstring GetAdapterDisplayName() const;
    void AddSystemMessage(const std::wstring& message);
    void ProcessPacket(const PacketInfo& info);
    bool AutoSelectAdapter();
    void OnPacketReceived(const PacketInfo& packet);
    void AddPacketToList(const PacketInfo& packet);
    void InitializeRulesList();
    void InitializeConnectionsList();
    void AddRule();
    void DeleteRule();
    void UpdateRulesList();
    void UpdateConnectionsList();

    HWND hwnd;
    HWND adapterInfoLabel;
    HINSTANCE hInstance;
    ListView rulesListView;
    ListView connectionsListView;
    PacketInterceptor packetInterceptor;
    std::string selectedAdapterIp;
    bool isCapturing;
    std::queue<PacketInfo> packetQueue;
    std::mutex packetMutex;
};