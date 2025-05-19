#pragma once
#include <Windows.h>
#include <memory>
#include <queue>
#include <mutex>
#include "packetinterceptor.h"
#include "listview.h"
#include "resource.h"
#include <map>
#include <unordered_map>
#include <string>
#include <fstream>
#include <deque>

#define WM_UPDATE_PACKET (WM_USER + 1)

class MainWindow {
public:
    enum ControlIds {
        ID_START_CAPTURE = 1003,
        ID_STOP_CAPTURE = 1004,
        ID_ADD_RULE = 1005,
        ID_DELETE_RULE = 1006,
        ID_SAVE_PACKETS = 2001,
        ID_CLEAR_SAVED_PACKETS = 2002
    };

    MainWindow();
    ~MainWindow();

    void UpdateAdapterInfo();
    bool Initialize(HINSTANCE hInstance);
    void Show(int nCmdShow);

protected:
    void OnStartCapture();
    void OnStopCapture();
    void OnSelectAdapter();
    bool CreateControls();
    void ShowAdapterSelectionDialog();
    static bool IsWifiAdapter(const std::string& description);

private:
    static const int WINDOW_WIDTH = 850;
    static const int WINDOW_HEIGHT = 600;
    static const int MARGIN = 10;
    static const int BUTTON_WIDTH = 120;
    static const int BUTTON_HEIGHT = 30;
    static const int LABEL_HEIGHT = 20;
    static const int COMBO_HEIGHT = 200;
    static const int COMBO_WIDTH = 250;

    std::deque<PacketInfo> packetQueue;
    std::mutex packetMutex;
    static const size_t MAX_QUEUE_SIZE = 1000;
    const size_t MAX_DISPLAYED_PACKETS = 5000;

    // Помещаем новый пакет (вызывается из PacketInterceptor callback)
    void PushPacket(const PacketInfo& pkt) {
        std::lock_guard<std::mutex> lock(packetMutex);
        if (packetQueue.size() >= MAX_QUEUE_SIZE) {
            packetQueue.pop_front(); // удаляем самый старый
        }
        packetQueue.push_back(pkt);
    }

    void ProcessPacketBatch();

    std::mutex groupedPacketsMutex;
    std::map<std::string, GroupedPacketInfo> groupedPackets;
    // Новый: map для каждого адаптера
    std::unordered_map<std::string, std::map<std::string, GroupedPacketInfo>> adapterPackets;

    static const size_t UPDATE_INTERVAL = 1000;

    static std::wstring FormatFileSize(size_t bytes);

    void UpdateGroupedPackets();

    UINT_PTR timerId;

    static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK AdapterDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
    static std::wstring StringToWString(const std::string& str);
    static std::string WStringToString(const std::wstring& wstr);

    bool InitializeRulesList();
    bool InitializeConnectionsList(int yPosition);
    void DeleteRule();

    bool CreateMainWindow();
    void OnAdapterSelected();
    void StartCapture();
    void StopCapture();

    std::wstring GetAdapterDisplayName() const;
    void AddSystemMessage(const std::wstring& message);
    void ProcessPacket(const PacketInfo& info);
    bool AutoSelectAdapter();
    void OnPacketCaptured(const PacketInfo& packet);
    void AddRule();
    void UpdateRulesList();
    void UpdateConnectionsList();

    // Сохранение/загрузка/очистка списков
    void SaveAdapterPackets(const std::string& adapter);
    void LoadAdapterPackets(const std::string& adapter);
    void ClearSavedAdapterPackets(const std::string& adapter);

    HWND hwnd;
    HWND adapterInfoLabel;
    HINSTANCE hInstance;
    ListView rulesListView;
    ListView connectionsListView;
    PacketInterceptor packetInterceptor;
    std::string selectedAdapterIp;
    bool isCapturing;
};

namespace WindowConstants {
    constexpr int DEFAULT_WINDOW_WIDTH = 800;
    constexpr int DEFAULT_WINDOW_HEIGHT = 600;
    constexpr int DEFAULT_MARGIN = 10;
    constexpr int DEFAULT_BUTTON_WIDTH = 120;
    constexpr int DEFAULT_BUTTON_HEIGHT = 30;
    constexpr int DEFAULT_LABEL_HEIGHT = 20;
    constexpr int DEFAULT_COMBO_HEIGHT = 200;
    constexpr int DEFAULT_COMBO_WIDTH = 250;
}