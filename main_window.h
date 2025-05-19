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
#include <set>

#define WM_UPDATE_PACKET (WM_USER + 1)

class MainWindow {
public:
    enum ControlIds {
        ID_START_CAPTURE = 1503,
        ID_STOP_CAPTURE = 1504,
        ID_ADD_RULE = 1505,
        ID_DELETE_RULE = 1506,
        ID_SAVE_PACKETS = 1501,
        ID_CLEAR_SAVED_PACKETS = 1502
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
    void UpdateGroupedPacketsIncremental();
    void UpdateGroupedPacketsNoDuplicates();
    std::set<std::string> displayedKeys;

    const size_t MAX_DISPLAYED_PACKETS = 5000;
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

    // Константы для меню
    static const int CMD_PACKET_PROPERTIES = 3101;
    static const int CMD_COPY_SOURCE_IP = 3102;
    static const int CMD_COPY_DEST_IP = 3103;
    static const int CMD_BLOCK_IP = 3104;
    static const int CMD_WHOIS_IP = 3105;

    // Вспомогательные методы
    std::string GetPacketKeyFromListView(int index);
    std::shared_ptr<GroupedPacketInfo> GetPacketInfo(const std::string& key);
    void CopyToClipboard(const std::string& text);
    void AddBlockingRule(const std::string& ip);
    void ShowPacketProperties(int itemIndex);

    void OpenRulesDialog();
    void OpenSettingsDialog();

    static std::string GetProcessPath(DWORD processId);

    // Обработчики
    void OnContextMenu(HWND hwnd, int x, int y);
    void OnPacketCommand(WPARAM wParam);
    static INT_PTR CALLBACK PacketPropertiesDialogProc(HWND hwnd, UINT msg,
        WPARAM wParam, LPARAM lParam);

    std::wstring GetAdapterDisplayName() const;
    void AddSystemMessage(const std::wstring& message);
    void ProcessPacket(const PacketInfo& info);
    bool AutoSelectAdapter();
    bool OnPacketCaptured(const PacketInfo& packet);
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