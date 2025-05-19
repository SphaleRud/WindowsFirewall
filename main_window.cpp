#define _WIN32_WINNT 0x0600
#include "main_window.h"
#include <commctrl.h>
#include <windowsx.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#ifndef GAA_FLAG_INCLUDE_PREFIX
#define GAA_FLAG_INCLUDE_PREFIX 0x00000010
#endif

std::vector<AdapterInfo> GetAllAdapters() {
    std::vector<AdapterInfo> adapters;
    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);
    IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    DWORD ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(outBufLen);
        pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    }
    if (ret != NO_ERROR) return adapters;

    for (IP_ADAPTER_ADDRESSES* pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        if (pCurr->OperStatus == IfOperStatusUp) {
            AdapterInfo info;
            info.name = pCurr->AdapterName;
            info.description = pCurr->Description ? pCurr->Description : "";
            info.isActive = true;
            // IP
            for (IP_ADAPTER_UNICAST_ADDRESS* ua = pCurr->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN] = { 0 };
                    sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa->sin_addr), buf, sizeof(buf));
                    info.address = buf;
                    break;
                }
            }
            if (!info.address.empty())
                adapters.push_back(info);
        }
    }
    return adapters;
}

bool IsWifiAdapter(const std::string& description) {
    std::string lowerName = description;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    return lowerName.find("wireless") != std::string::npos ||
        lowerName.find("wifi") != std::string::npos ||
        lowerName.find("802.11") != std::string::npos;
}

std::string TimeTToString(const time_t& time) {
    std::ostringstream oss;
    tm tmTime;
    localtime_s(&tmTime, &time);
    oss << std::put_time(&tmTime, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string MainWindow::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring MainWindow::StringToWString(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

MainWindow::MainWindow() : hwnd(nullptr), hInstance(nullptr), adapterInfoLabel(nullptr), isCapturing(false) {}

MainWindow::~MainWindow() {
    adapterPackets.clear();
    if (packetInterceptor.IsCapturing()) {
        packetInterceptor.StopCapture();
    }
}

bool MainWindow::Initialize(HINSTANCE hInstance_) {
    hInstance = hInstance_;
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = MainWindow::MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowsFirewallClass";
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wc)) {
        OutputDebugStringA("Failed to register window class\n");
        return false;
    }

    hwnd = CreateWindowEx(
        0,
        L"WindowsFirewallClass",
        L"Windows Firewall",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        NULL,
        NULL,
        hInstance,
        this
    );

    if (!hwnd) {
        OutputDebugStringA("Failed to create window\n");
        return false;
    }

    if (!CreateControls()) {
        OutputDebugStringA("Failed to create controls\n");
        return false;
    }

    std::vector<AdapterInfo> adapters = GetAllAdapters();
    if (!adapters.empty()) {
        selectedAdapterIp = adapters[0].address;
        UpdateAdapterInfo();
    }

    if (!adapters.empty()) {
        HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
        SendMessage(comboBox, CB_SETCURSEL, 0, 0);
        selectedAdapterIp = adapters[0].address;
        UpdateAdapterInfo();
        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
    }

    PostMessage(hwnd, WM_APP + 1, 0, 0); // пользовательское сообщение для инициализации

    return true;
}

std::wstring MainWindow::FormatFileSize(size_t bytes) {
    try {
        if (bytes < 1024) {
            return std::to_wstring(bytes) + L" байт";
        }
        else if (bytes < 1024 * 1024) {
            double kb = static_cast<double>(bytes) / 1024.0;
            wchar_t buffer[64] = {};
            swprintf_s(buffer, L"%.2f КБ", kb);
            return buffer;
        }
        else {
            double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
            wchar_t buffer[64] = {};
            swprintf_s(buffer, L"%.2f МБ", mb);
            return buffer;
        }
    }
    catch (...) {
        return L"??? байт";
    }
}

bool MainWindow::CreateMainWindow() {
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"WindowsFirewallClass";

    if (!RegisterClassExW(&wc)) {
        return false;
    }

    hwnd = CreateWindowExW(
        0,
        L"WindowsFirewallClass",
        L"Windows Firewall",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        nullptr,
        nullptr,
        hInstance,
        this
    );
    if (!hwnd) {
        return false;
    }
    // Создаем контролы
    return CreateControls();
}

void MainWindow::SaveAdapterPackets(const std::string& adapter) {
    if (adapter.empty()) {
        MessageBox(hwnd, L"Адаптер не выбран!", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }
    char buf[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buf);
    std::string filename = "packets_" + adapter + ".csv";
    std::ofstream fout(filename, std::ios::trunc);
    if (!fout) {
        MessageBox(hwnd, L"Не удалось создать файл!", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }
    if (groupedPackets.empty()) {
        MessageBox(hwnd, L"Нет ни одного пакета для сохранения!", L"Инфо", MB_OK | MB_ICONINFORMATION);
        return;
    }
    for (const auto& pair : groupedPackets) {
        const auto& pkt = pair.second;
        fout << pkt.sourceIp << ','
            << pkt.destIp << ','
            << pkt.protocol << ','
            << pkt.processName << ','
            << pkt.processId << ','
            << pkt.time << ','
            << pkt.sourcePort << ','
            << pkt.destPort << ','
            << (pkt.direction == PacketDirection::Incoming ? "in" : "out") << '\n';
    }
    fout.close();
    MessageBox(hwnd, L"Список успешно сохранён!", L"Инфо", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::LoadAdapterPackets(const std::string& adapter) {
    std::string filename = "packets_" + adapter + ".csv";
    std::ifstream fin(filename);
    if (!fin) return;
    std::map<std::string, GroupedPacketInfo> loaded;
    std::string line;
    while (std::getline(fin, line)) {
        std::stringstream ss(line);
        GroupedPacketInfo pkt;
        std::string dir;
        std::getline(ss, pkt.sourceIp, ',');
        std::getline(ss, pkt.destIp, ',');
        std::getline(ss, pkt.protocol, ',');
        std::getline(ss, pkt.processName, ',');
        std::string pidstr;
        std::getline(ss, pidstr, ',');
        pkt.processId = static_cast<uint32_t>(std::stoul(pidstr));
        std::getline(ss, pkt.time, ',');
        std::string sp, dp;
        std::getline(ss, sp, ',');
        pkt.sourcePort = static_cast<uint16_t>(std::stoi(sp));
        std::getline(ss, dp, ',');
        pkt.destPort = static_cast<uint16_t>(std::stoi(dp));
        std::getline(ss, dir, ',');
        pkt.direction = (dir == "in") ? PacketDirection::Incoming : PacketDirection::Outgoing;
        loaded[pkt.GetKey()] = pkt;
    }
    fin.close();
    adapterPackets[adapter] = loaded;
}

void MainWindow::ClearSavedAdapterPackets(const std::string& adapter) {
    std::string filename = "packets_" + adapter + ".csv";
    std::remove(filename.c_str());
    adapterPackets[adapter].clear();
    if (adapter == selectedAdapterIp) {
        groupedPackets.clear();
        UpdateGroupedPackets();
    }
    MessageBox(hwnd, L"Список успешно удалён!", L"Инфо", MB_OK | MB_ICONINFORMATION);
}

LRESULT MainWindow::HandlePacketUpdate(WPARAM wParam, LPARAM lParam) {
    PacketInfo* packetInfo = reinterpret_cast<PacketInfo*>(lParam);
    if (packetInfo) {
        AddPacketToList(*packetInfo);
        delete packetInfo;
    }
    return 0;
}

void MainWindow::ProcessPacket(const PacketInfo& info) {
    std::wstring time = StringToWString(info.time);
    std::wstring direction = (info.direction == PacketDirection::Incoming) ? L"Incoming" : L"Outgoing";
    std::wstring sourceIp = StringToWString(info.sourceIp);
    std::wstring destIp = StringToWString(info.destIp);
    std::wstring protocol = StringToWString(info.protocol);
    std::wstring processName = StringToWString(info.processName);

    std::wstring packetInfo = time + L" | " +
        direction + L" | " +
        sourceIp + L":" + std::to_wstring(info.sourcePort) + L" → " +
        destIp + L":" + std::to_wstring(info.destPort) + L" | " +
        protocol + L" | " +
        std::to_wstring(info.size) + L" bytes | " +
        processName;

    AddSystemMessage(packetInfo);
}

void MainWindow::UpdateAdapterInfo() {
    if (!selectedAdapterIp.empty()) {
        auto adapters = GetAllAdapters();
        for (const auto& adapter : adapters) {
            if (adapter.address == selectedAdapterIp) {
                std::wstring info = L"Selected adapter: " + StringToWString(adapter.description) +
                    L" (" + StringToWString(adapter.address) + L")";
                SetWindowText(adapterInfoLabel, info.c_str());
                return;
            }
        }
    }
    SetWindowText(adapterInfoLabel, L"No adapter selected");
}

std::wstring MainWindow::GetAdapterDisplayName() const {
    auto adapters = GetAllAdapters();
    if (adapters.empty()) {
        return L"No adapters available";
    }
    for (const auto& adapter : adapters) {
        if (adapter.address == selectedAdapterIp) {
            return StringToWString(adapter.description + " (" + adapter.address + ")");
        }
    }
    return L"Unknown Adapter";
}

void MainWindow::OnStartCapture() {
    if (selectedAdapterIp.empty()) {
        MessageBox(hwnd, L"Please select an adapter first", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    OutputDebugStringA("OnStartCapture: SetPacketCallback called!\n");
    packetInterceptor.SetPacketCallback([this](const PacketInfo& packet) {
        OutputDebugStringA("Packet callback called!\n");
        PacketInfo* packetCopy = new PacketInfo(packet);
        PostMessage(hwnd, WM_APP + 2, 0, (LPARAM)packetCopy);
        });
    if (packetInterceptor.StartCapture()) {
        isCapturing = true;
        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_STOP_CAPTURE), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_ADAPTER_COMBO), FALSE);
    }
    else {
        MessageBox(hwnd, L"Failed to start capture", L"Error", MB_OK | MB_ICONERROR);
    }
}

void MainWindow::OnStopCapture() {
    if (isCapturing) {
        packetInterceptor.StopCapture();
        isCapturing = false;
        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_STOP_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_ADAPTER_COMBO), TRUE);
        AddSystemMessage(L"Capture stopped");
    }
}

void MainWindow::OnSelectAdapter() {
    DialogBoxParam(hInstance,
        MAKEINTRESOURCE(IDD_SELECT_ADAPTER),
        hwnd,
        AdapterDialogProc,
        reinterpret_cast<LPARAM>(this));
}

INT_PTR CALLBACK MainWindow::AdapterDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_INITDIALOG: {
        MainWindow* window = reinterpret_cast<MainWindow*>(lParam);
        if (!window) return FALSE;
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        auto adapters = GetAllAdapters();
        HWND hwndList = GetDlgItem(hwndDlg, IDC_ADAPTER_LIST);
        if (!hwndList) return FALSE;
        for (const auto& adapter : adapters) {
            std::wstring displayName = MainWindow::StringToWString(adapter.description);
            if (!displayName.empty()) {
                int index = ListBox_AddString(hwndList, displayName.c_str());
                if (index != LB_ERR) {
                    ListBox_SetItemData(hwndList, index, new std::string(adapter.address));
                }
            }
        }
        return TRUE;
    }
    case WM_COMMAND: {
        MainWindow* window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwndDlg, GWLP_USERDATA));
        if (!window) return FALSE;
        switch (LOWORD(wParam)) {
        case IDOK: {
            HWND hwndList = GetDlgItem(hwndDlg, IDC_ADAPTER_LIST);
            if (!hwndList) return FALSE;
            int selectedIndex = ListBox_GetCurSel(hwndList);
            if (selectedIndex != LB_ERR) {
                std::string* adapterAddr = reinterpret_cast<std::string*>(ListBox_GetItemData(hwndList, selectedIndex));
                if (adapterAddr) {
                    window->selectedAdapterIp = *adapterAddr;
                    delete adapterAddr;
                }
            }
            int count = ListBox_GetCount(hwndList);
            for (int i = 0; i < count; ++i) {
                std::string* data = reinterpret_cast<std::string*>(ListBox_GetItemData(hwndList, i));
                delete data;
            }
            EndDialog(hwndDlg, IDOK);
            window->UpdateAdapterInfo();
            return TRUE;
        }
        case IDCANCEL:
            HWND hwndList = GetDlgItem(hwndDlg, IDC_ADAPTER_LIST);
            if (hwndList) {
                int count = ListBox_GetCount(hwndList);
                for (int i = 0; i < count; ++i) {
                    std::string* data = reinterpret_cast<std::string*>(ListBox_GetItemData(hwndList, i));
                    delete data;
                }
            }
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    case WM_DESTROY: {
        HWND hwndList = GetDlgItem(hwndDlg, IDC_ADAPTER_LIST);
        if (hwndList) {
            int count = ListBox_GetCount(hwndList);
            for (int i = 0; i < count; ++i) {
                std::string* data = reinterpret_cast<std::string*>(ListBox_GetItemData(hwndList, i));
                delete data;
            }
        }
        return TRUE;
    }
    }
    return FALSE;
}

bool MainWindow::AutoSelectAdapter() {
    auto adapters = GetAllAdapters();
    if (adapters.empty()) {
        AddSystemMessage(L"No network adapters found");
        return false;
    }
    for (const auto& adapter : adapters) {
        if (IsWifiAdapter(adapter.description)) {
            selectedAdapterIp = adapter.address;
            UpdateAdapterInfo();
            AddSystemMessage(L"Selected WiFi adapter: " + GetAdapterDisplayName());
            return true;
        }
    }
    selectedAdapterIp = adapters[0].address;
    UpdateAdapterInfo();
    AddSystemMessage(L"Selected adapter: " + GetAdapterDisplayName());
    return true;
}

bool MainWindow::CreateControls() {
    adapterInfoLabel = CreateWindowEx(
        0, WC_STATIC, L"Selecting adapter...",
        WS_CHILD | WS_VISIBLE,
        MARGIN, MARGIN,
        WINDOW_WIDTH - 2 * MARGIN, LABEL_HEIGHT,
        hwnd, NULL,
        hInstance, NULL
    );
    int buttonY = MARGIN * 2 + LABEL_HEIGHT;
    CreateWindowEx(
        0, WC_BUTTON, L"Start Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_START_CAPTURE,
        hInstance, NULL
    );
    CreateWindowEx(
        0, WC_BUTTON, L"Stop Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        MARGIN + BUTTON_WIDTH + MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_STOP_CAPTURE,
        hInstance, NULL
    );
    CreateWindowEx(
        0, WC_BUTTON, L"Save List",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN + 2 * (BUTTON_WIDTH + MARGIN), buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)ID_SAVE_PACKETS,
        hInstance, NULL
    );
    CreateWindowEx(
        0, WC_BUTTON, L"Clear Saved",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN + 3 * (BUTTON_WIDTH + MARGIN), buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)ID_CLEAR_SAVED_PACKETS,
        hInstance, NULL
    );
    HWND adapterCombo = CreateWindowEx(
        0, WC_COMBOBOX, L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        MARGIN + 4 * (BUTTON_WIDTH + MARGIN) + MARGIN, buttonY,
        COMBO_WIDTH, COMBO_HEIGHT,
        hwnd, (HMENU)IDC_ADAPTER_COMBO,
        hInstance, NULL
    );
    auto adapters = GetAllAdapters();
    for (const auto& adapter : adapters) {
        SendMessageW(adapterCombo, CB_ADDSTRING, 0,
            (LPARAM)StringToWString(adapter.description).c_str());
    }
    int listY = buttonY + BUTTON_HEIGHT + MARGIN;
    if (!InitializeConnectionsList(listY)) {
        return false;
    }
    return true;
}

void MainWindow::ShowAdapterSelectionDialog() {
    DialogBoxParam(
        hInstance,
        MAKEINTRESOURCE(IDD_ADAPTER_DIALOG),
        hwnd,
        AdapterDialogProc,
        reinterpret_cast<LPARAM>(this)
    );
}

bool MainWindow::InitializeRulesList() {
    if (!rulesListView.Initialize(hwnd, 10, 40, 760, 200, (HMENU)ID_RULES_LIST, hInstance)) {
        return false;
    }
    const std::vector<ListView::Column> columns = {
        {L"Protocol", 100},
        {L"Local Address", 150},
        {L"Remote Address", 150},
        {L"Action", 100},
        {L"Description", 260}
    };
    for (size_t i = 0; i < columns.size(); ++i) {
        if (!rulesListView.AddColumn(columns[i].text, columns[i].width, i)) {
            return false;
        }
    }
    return true;
}

bool MainWindow::InitializeConnectionsList(int yPosition) {
    if (!connectionsListView.Initialize(hwnd, MARGIN, yPosition,
        WINDOW_WIDTH - 2 * MARGIN, WINDOW_HEIGHT - yPosition - MARGIN,
        (HMENU)IDC_PACKET_LIST, hInstance)) {
        return false;
    }
    const struct ColumnInfo {
        const wchar_t* text;
        int width;
    } columns[] = {
        {L"Направление", 80},
        {L"IP источника", 90},
        {L"Порт источника", 60},
        {L"IP назначения", 90},
        {L"Порт назначения", 60},
        {L"Протокол", 80},
        {L"PID процесса", 80},
        {L"Процесс", 150}
    };
    for (int i = 0; i < _countof(columns); i++) {
        if (!connectionsListView.AddColumn(columns[i].text, columns[i].width, i)) {
            wchar_t debug[256];
            swprintf_s(debug, L"Failed to add column %d: %s\n", i, columns[i].text);
            OutputDebugString(debug);
            return false;
        }
    }
    return true;
}

void MainWindow::OnPacketReceived(const PacketInfo& info) {
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        packetQueue.push(info);
    }
    PostMessage(hwnd, WM_UPDATE_PACKET, 0, 0);
}

const size_t MAX_DISPLAYED_PACKETS = 100;

void MainWindow::UpdateGroupedPackets() {
    connectionsListView.SetRedraw(false);
    connectionsListView.Clear();
    std::map<std::string, GroupedPacketInfo> copy;
    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        copy = groupedPackets;
    }
    std::vector<const GroupedPacketInfo*> lastPackets;
    for (const auto& pair : copy)
        lastPackets.push_back(&pair.second);
    size_t total = lastPackets.size();
    size_t start = (total > MAX_DISPLAYED_PACKETS) ? total - MAX_DISPLAYED_PACKETS : 0;
    for (size_t i = start; i < total; ++i) {
        const auto& packet = *lastPackets[i];
        std::vector<std::wstring> items;
        items.reserve(8);
        items.push_back(packet.direction == PacketDirection::Incoming ? L"Входящий" : L"Исходящий");
        items.push_back(StringToWString(packet.sourceIp));
        items.push_back(std::to_wstring(packet.sourcePort));
        items.push_back(StringToWString(packet.destIp));
        items.push_back(std::to_wstring(packet.destPort));
        items.push_back(StringToWString(packet.protocol));
        items.push_back(std::to_wstring(packet.processId));
        items.push_back(StringToWString(packet.processName));
        connectionsListView.AddItem(items);
    }
    OutputDebugStringA(("groupedPackets size: " + std::to_string(copy.size()) + "\n").c_str());
    connectionsListView.SetRedraw(true);
    InvalidateRect(connectionsListView.GetHandle(), NULL, TRUE);
}

void MainWindow::OnPacketCaptured(const PacketInfo& packet) {
    try {
        GroupedPacketInfo groupInfo;
        groupInfo.sourceIp = packet.sourceIp;
        groupInfo.destIp = packet.destIp;
        groupInfo.protocol = packet.protocol;
        groupInfo.processId = packet.processId;
        groupInfo.processName = packet.processName;
        groupInfo.sourcePort = packet.sourcePort;
        groupInfo.destPort = packet.destPort;
        groupInfo.direction = packet.direction;
        std::string key = groupInfo.GetKey();
        {
            std::lock_guard<std::mutex> lock(groupedPacketsMutex);
            groupedPackets[key] = groupInfo;
            if (!selectedAdapterIp.empty()) {
                adapterPackets[selectedAdapterIp] = groupedPackets;
            }
        }
        OutputDebugStringA(("Captured packet with key: " + key + "\n").c_str());
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("OnPacketCaptured error: " + std::string(e.what()) + "\n").c_str());
    }
}

void MainWindow::AddPacketToList(const PacketInfo& info) {
    if (!connectionsListView) {
        OutputDebugString(L"ListView is not initialized!\n");
        return;
    }
    std::vector<std::wstring> items;
    items.reserve(8);
    items.push_back(info.direction == PacketDirection::Incoming ? L"Входящий" : L"Исходящий");
    items.push_back(StringToWString(info.sourceIp));
    items.push_back(std::to_wstring(info.sourcePort));
    items.push_back(StringToWString(info.destIp));
    items.push_back(std::to_wstring(info.destPort));
    items.push_back(StringToWString(info.protocol));
    items.push_back(std::to_wstring(info.processId));
    items.push_back(StringToWString(info.processName));
    int index = connectionsListView.AddItem(items);
    if (index < 0) {
        OutputDebugString(L"Failed to add item to ListView!\n");
        return;
    }
    ListView_EnsureVisible(connectionsListView.GetHandle(), index, FALSE);
}

void MainWindow::StartCapture() {
    if (selectedAdapterIp.empty()) {
        MessageBox(hwnd, L"Please select a network adapter first", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    OutputDebugString((L"Starting capture on adapter: " +
        StringToWString(selectedAdapterIp) + L"\n").c_str());
    if (packetInterceptor.StartCapture()) {
        isCapturing = true;
        EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), TRUE);
        std::wstring message = L"Started capturing on " + GetAdapterDisplayName();
        AddSystemMessage(message);
        OutputDebugString((L"Started capture: " +
            StringToWString(selectedAdapterIp) + L"\n").c_str());
    }
    else {
        MessageBox(hwnd, L"Failed to start capture", L"Error", MB_OK | MB_ICONERROR);
        OutputDebugString((L"Failed to start capture on adapter: " +
            StringToWString(selectedAdapterIp) + L"\n").c_str());
    }
}

void MainWindow::StopCapture() {
    if (!packetInterceptor.IsCapturing()) return;
    packetInterceptor.StopCapture();
    isCapturing = false;
    EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), TRUE);
    EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), FALSE);
    AddSystemMessage(L"Stopped capturing");
    OutputDebugString(L"Stopped capture\n");
}

void MainWindow::AddSystemMessage(const std::wstring& message) {
    if (connectionsListView.GetHandle()) {
        std::vector<std::wstring> items = { message };
        connectionsListView.AddItem(items);
    }
}

void MainWindow::OnAdapterSelected() {
    if (!selectedAdapterIp.empty()) {
        adapterPackets[selectedAdapterIp] = groupedPackets;
    }
    HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
    int selectedIndex = SendMessage(comboBox, CB_GETCURSEL, 0, 0);
    if (selectedIndex != CB_ERR) {
        auto adapters = GetAllAdapters();
        if (selectedIndex < static_cast<int>(adapters.size())) {
            selectedAdapterIp = adapters[selectedIndex].address;
            UpdateAdapterInfo();
            LoadAdapterPackets(selectedAdapterIp);
            if (adapterPackets.count(selectedAdapterIp) && !adapterPackets[selectedAdapterIp].empty()) {
                groupedPackets = adapterPackets[selectedAdapterIp];
            }
            else {
                groupedPackets.clear();
            }
            UpdateGroupedPackets();
            EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
        }
    }
}

LRESULT CALLBACK MainWindow::MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = nullptr;
    if (msg == WM_CREATE) {
        CREATESTRUCT* createStruct = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = reinterpret_cast<MainWindow*>(createStruct->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        SetTimer(hwnd, 1, UPDATE_INTERVAL, NULL);
    }
    else {
        window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    if (window) {
        switch (msg) {
        case WM_APP + 1: {
            auto adapters = GetAllAdapters();
            if (!adapters.empty()) {
                HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
                SendMessage(comboBox, CB_SETCURSEL, 0, 0);
                window->selectedAdapterIp = adapters[0].address;
                window->UpdateAdapterInfo();
                EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
                window->LoadAdapterPackets(window->selectedAdapterIp);
                if (window->adapterPackets.count(window->selectedAdapterIp) &&
                    !window->adapterPackets[window->selectedAdapterIp].empty()) {
                    window->groupedPackets = window->adapterPackets[window->selectedAdapterIp];
                }
                else {
                    window->groupedPackets.clear();
                }
                window->UpdateGroupedPackets();
            }
            return 0;
        }
        case WM_APP + 2: {
            OutputDebugStringA("WM_APP+2 received\n");
            PacketInfo* packet = (PacketInfo*)lParam;
            if (packet) {
                window->OnPacketCaptured(*packet);
                delete packet;
            }
            return 0;
        }
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);
            switch (wmId) {
            case ID_SAVE_PACKETS:
                if (wmEvent == BN_CLICKED) {
                    window->SaveAdapterPackets(window->selectedAdapterIp);
                    return 0;
                }
                break;
            case ID_CLEAR_SAVED_PACKETS:
                if (wmEvent == BN_CLICKED) {
                    window->ClearSavedAdapterPackets(window->selectedAdapterIp);
                    return 0;
                }
                break;
            case IDC_START_CAPTURE:
                if (wmEvent == BN_CLICKED) {
                    window->OnStartCapture();
                    return 0;
                }
                break;
            case IDC_STOP_CAPTURE:
                if (wmEvent == BN_CLICKED) {
                    window->OnStopCapture();
                    return 0;
                }
                break;
            case IDC_ADAPTER_COMBO:
                if (wmEvent == CBN_SELCHANGE) {
                    window->OnAdapterSelected();
                    return 0;
                }
                break;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }
        case WM_TIMER:
            if (wParam == 1) {
                window->UpdateGroupedPackets();
            }
            break;
        case WM_CLOSE: {
            if (window->isCapturing) {
                window->OnStopCapture();
            }
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_DESTROY: {
            KillTimer(hwnd, 1);
            PostQuitMessage(0);
            return 0;
        }
                       break;
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void MainWindow::Show(int nCmdShow) {
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    if (packetInterceptor.Initialize()) {
        auto adapters = GetAllAdapters();
        if (!adapters.empty()) {
            if (selectedAdapterIp.empty()) {
                AutoSelectAdapter();
            }
            UpdateAdapterInfo();
        }
    }
}

void MainWindow::UpdateRulesList() {}
void MainWindow::UpdateConnectionsList() {}
void MainWindow::AddRule() {
    MessageBox(hwnd, L"Add Rule functionality will be implemented soon",
        L"Not Implemented", MB_OK | MB_ICONINFORMATION);
}
void MainWindow::DeleteRule() {
    int selectedIndex = rulesListView.GetSelectedIndex();
    if (selectedIndex == -1) {
        MessageBox(hwnd, L"Please select a rule to delete",
            L"No Rule Selected", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (MessageBox(hwnd, L"Are you sure you want to delete this rule?",
        L"Confirm Delete", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        rulesListView.DeleteItem(selectedIndex);
    }
}