#define WIN32_LEAN_AND_MEAN
#include "main_window.h"
#include <commctrl.h>
#include <windowsx.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <mutex>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ID компонентов
#define ID_SAVE_PACKETS 2001
#define ID_CLEAR_SAVED_PACKETS 2002
#define ID_RULES_LIST 1001
#define ID_CONNECTIONS_LIST 1002
#define ID_ADD_RULE 1003
#define ID_DELETE_RULE 1004
#define ID_START_CAPTURE 1005
#define ID_STOP_CAPTURE 1006

std::string TimeTToString(const time_t& time) {
    std::ostringstream oss;
    tm tmTime;
    localtime_s(&tmTime, &time);
    oss << std::put_time(&tmTime, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string WStringToString(const std::wstring& wstr) {
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

MainWindow::MainWindow() : hwnd(nullptr), hInstance(nullptr), adapterInfoLabel(nullptr) {
}

MainWindow::~MainWindow() {
    adapterPackets.clear();
    if (packetInterceptor.IsCapturing()) {
        packetInterceptor.StopCapture();
    }
}

bool MainWindow::Initialize(HINSTANCE hInstance) {
    // Регистрируем класс окна
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

    // Создаем главное окно
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

    // Получаем список сетевых адаптеров
    std::vector<AdapterInfo> adapters = packetInterceptor.GetAdapters();
    if (!adapters.empty()) {
        selectedAdapterIp = adapters[0].address;
        // Вызываем UpdateAdapterInfo без параметров
        UpdateAdapterInfo();
    }

    // Автоматически выбираем первый адаптер
    if (!adapters.empty()) {
        HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
        SendMessage(comboBox, CB_SETCURSEL, 0, 0);
        selectedAdapterIp = adapters[0].address;
        UpdateAdapterInfo();
        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
    }

    // Инициализируем адаптер сразу после создания окна
    PostMessage(hwnd, WM_APP + 1, 0, 0); // Отправляем пользовательское сообщение для инициализации

    return true;
}

// Статическая функция форматирования размера файла
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
    // Показываем путь для отладки
    // MessageBoxA(hwnd, buf, "Текущая папка", MB_OK);

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
    // Преобразование времени
    std::wstring time = StringToWString(info.time);

    // Правильное преобразование PacketDirection в строку
    std::wstring direction = (info.direction == PacketDirection::Incoming) ? L"Incoming" : L"Outgoing";

    // Преобразование IP адресов
    std::wstring sourceIp = StringToWString(info.sourceIp);
    std::wstring destIp = StringToWString(info.destIp);

    // Преобразование протокола
    std::wstring protocol = StringToWString(info.protocol);

    // Преобразование имени процесса
    std::wstring processName = StringToWString(info.processName);

    // Форматируем строку для отображения
	std::wstring packetInfo = time + L" | " +
        direction + L" | " +
        sourceIp + L":" + std::to_wstring(info.sourcePort) + L" → " +
        destIp + L":" + std::to_wstring(info.destPort) + L" | " +
        protocol + L" | " +
        std::to_wstring(info.size) + L" bytes | " +
        processName;

    // Добавляем сообщение в журнал
    AddSystemMessage(packetInfo);
}

void MainWindow::UpdateAdapterInfo() {
    if (!selectedAdapterIp.empty()) {
        auto adapters = packetInterceptor.GetAdapters();
        for (const auto& adapter : adapters) {
            if (adapter.address == selectedAdapterIp) {
                std::wstring info = L"Selected adapter: " + StringToWString(adapter.description) +
                    L" (" + StringToWString(adapter.address) + L")";
                SetWindowText(adapterInfoLabel, info.c_str());
                return; // Добавляем return после установки текста
            }
        }
    }

    // Если адаптер не найден
    SetWindowText(adapterInfoLabel, L"No adapter selected");
}

std::wstring MainWindow::GetAdapterDisplayName() const {
    // Заменяем !packetInterceptor на более конкретную проверку
    if (!packetInterceptor.IsCapturing()) {
        return L"Initializing...";
    }

    if (selectedAdapterIp.empty()) {
        return L"Not selected";
    }

    // Заменяем -> на .
    auto adapters = packetInterceptor.GetNetworkAdapters();
    if (adapters.empty()) {
        return L"No adapters available";
    }

    // Исправляем цикл и проверку адаптера
    for (const auto& adapter : adapters) {
        if (adapter.name == selectedAdapterIp) {
            return StringToWString(adapter.name + " (" + selectedAdapterIp + ")");
        }
    }

    return L"Unknown Adapter";
}

void MainWindow::OnStartCapture() {
     if (selectedAdapterIp.empty()) {
         MessageBox(hwnd, L"Please select an adapter first", L"Error", MB_OK | MB_ICONERROR);
         return;
     }

     // Устанавливаем callback для обработки пакетов
     OutputDebugStringA("OnStartCapture: SetPacketCallback called!\n");
     packetInterceptor.SetPacketCallback([this](const PacketInfo& packet) {
         OutputDebugStringA("Packet callback called!\n");
         // Используем PostMessage для безопасного обновления UI из другого потока
         PacketInfo* packetCopy = new PacketInfo(packet);
         PostMessage(hwnd, WM_APP + 2, 0, (LPARAM)packetCopy);
         });

     if (packetInterceptor.StartCapture(selectedAdapterIp)) {
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
        // Получаем указатель на главное окно из lParam
        MainWindow* window = reinterpret_cast<MainWindow*>(lParam);
        if (!window) return FALSE;

        // Сохраняем указатель на главное окно
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));

        // Получаем список адаптеров
        auto adapters = window->packetInterceptor.GetNetworkAdapters();
        HWND hwndList = GetDlgItem(hwndDlg, IDC_ADAPTER_LIST);
        if (!hwndList) return FALSE;

        // Заполняем список адаптеров
        for (const auto& adapter : adapters) {
            std::wstring displayName = StringToWString(adapter.description);
            if (!displayName.empty()) {
                int index = ListBox_AddString(hwndList, displayName.c_str());
                if (index != LB_ERR) {
                    // Сохраняем имя адаптера как пользовательские данные
                    ListBox_SetItemData(hwndList, index, reinterpret_cast<LPARAM>(new std::string(adapter.name)));
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
                // Получаем сохраненное имя адаптера
                std::string* adapterName = reinterpret_cast<std::string*>(ListBox_GetItemData(hwndList, selectedIndex));
                if (adapterName) {
                    window->selectedAdapterIp = *adapterName;
                    delete adapterName; // Освобождаем память
                }
            }

            // Очищаем все данные списка перед закрытием
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
            // Очищаем данные списка перед закрытием
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
        // На всякий случай очищаем данные списка и здесь
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
    // Проверяем адаптеры напрямую
    auto adapters = packetInterceptor.GetNetworkAdapters();
    if (adapters.empty()) {
        AddSystemMessage(L"No network adapters found");
        return false;
    }

    for (const auto& adapter : adapters) {
        if (packetInterceptor.IsWifiAdapter(adapter.description)) {
            selectedAdapterIp = adapter.name;
            UpdateAdapterInfo();
            AddSystemMessage(L"Selected WiFi adapter: " + GetAdapterDisplayName());
            return true;
        }
    }

    selectedAdapterIp = adapters[0].name;
    UpdateAdapterInfo();
    AddSystemMessage(L"Selected adapter: " + GetAdapterDisplayName());
    return true;
}


bool MainWindow::CreateControls() {
    // Создаем метку для информации об адаптере
    adapterInfoLabel = CreateWindowEx(
        0, WC_STATIC, L"Selecting adapter...",
        WS_CHILD | WS_VISIBLE,
        MARGIN, MARGIN,
        WINDOW_WIDTH - 2 * MARGIN, LABEL_HEIGHT,
        hwnd, NULL,
        hInstance, NULL
    );

    // Кнопки управления
    int buttonY = MARGIN * 2 + LABEL_HEIGHT;

    // Кнопка Start Capture
    CreateWindowEx(
        0, WC_BUTTON, L"Start Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_START_CAPTURE,
        hInstance, NULL
    );

    // Кнопка Stop Capture
    CreateWindowEx(
        0, WC_BUTTON, L"Stop Capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        MARGIN + BUTTON_WIDTH + MARGIN, buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)IDC_STOP_CAPTURE,
        hInstance, NULL
    );

    // Кнопка Сохранить список
    CreateWindowEx(
        0, WC_BUTTON, L"Save List",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN + 2 * (BUTTON_WIDTH + MARGIN), buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)ID_SAVE_PACKETS,
        hInstance, NULL
    );
    // Кнопка Очистить сохранённое
    CreateWindowEx(
        0, WC_BUTTON, L"Clear Saved",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        MARGIN + 3 * (BUTTON_WIDTH + MARGIN), buttonY,
        BUTTON_WIDTH, BUTTON_HEIGHT,
        hwnd, (HMENU)ID_CLEAR_SAVED_PACKETS,
        hInstance, NULL
    );

    // Комбо-бокс размещаем справа от всех кнопок с большим отступом
    HWND adapterCombo = CreateWindowEx(
        0, WC_COMBOBOX, L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        MARGIN + 4 * (BUTTON_WIDTH + MARGIN) + MARGIN, buttonY, // <-- сдвиг вправо
        COMBO_WIDTH, COMBO_HEIGHT,
        hwnd, (HMENU)IDC_ADAPTER_COMBO,
        hInstance, NULL
    );

    // Заполняем комбо-бокс адаптерами
    auto adapters = packetInterceptor.GetAdapters();
    for (const auto& adapter : adapters) {
        SendMessageW(adapterCombo, CB_ADDSTRING, 0,
            (LPARAM)StringToWString(adapter.description).c_str());
    }

    // Инициализируем список соединений
    int listY = buttonY + BUTTON_HEIGHT + MARGIN;
    if (!InitializeConnectionsList(listY)) {
        return false;
    }
/*
    // ListView для пакетов
    int listY = buttonY + BUTTON_HEIGHT + MARGIN;
    if (!connectionsListView.Initialize(hwnd, MARGIN, listY,
        WINDOW_WIDTH - 2 * MARGIN, WINDOW_HEIGHT - listY - MARGIN,
        (HMENU)IDC_PACKET_LIST, hInstance)) {
        return false;
    }

    // Добавляем колонки
    connectionsListView.AddColumn(L"Направление", 80, 0);  
    connectionsListView.AddColumn(L"Источник", 180, 1);    
    connectionsListView.AddColumn(L"Назначение", 180, 2);  
    connectionsListView.AddColumn(L"Протокол", 80, 3);     
    connectionsListView.AddColumn(L"Процесс", 150, 4);     
*/
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

// Инициализация списков
bool MainWindow::InitializeRulesList() {
    if (!rulesListView.Initialize(hwnd, 10, 40, 760, 200, (HMENU)ID_RULES_LIST, hInstance)) {
        return false;
    }

    // Добавляем колонки
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
    // Инициализируем ListView
    if (!connectionsListView.Initialize(hwnd, MARGIN, yPosition,
        WINDOW_WIDTH - 2 * MARGIN, WINDOW_HEIGHT - yPosition - MARGIN,
        (HMENU)IDC_PACKET_LIST, hInstance)) {
        return false;
    }

    // Проверим количество и порядок колонок, добавив отладочный вывод
    OutputDebugString(L"Initializing columns...\n");

    const struct ColumnInfo {
        const wchar_t* text;
        int width;
    } columns[] = {
        {L"Направление", 80},     // 0
        {L"IP источника", 90},   // 1
        {L"Порт источника", 60},  // 2
        {L"IP назначения", 90},  // 3
        {L"Порт назначения", 60}, // 4
        {L"Протокол", 80},        // 5
		{L"PID процесса", 80}, // 6
        {L"Процесс", 150}         // 7
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

// Обработка пакетов
void MainWindow::OnPacketReceived(const PacketInfo& info) {
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        packetQueue.push(info);
    }
    PostMessage(hwnd, WM_UPDATE_PACKET, 0, 0);
}

const size_t MAX_DISPLAYED_PACKETS = 100;

#include <vector>
// ...
void MainWindow::UpdateGroupedPackets() {
    connectionsListView.SetRedraw(false);
    connectionsListView.Clear();

    std::map<std::string, GroupedPacketInfo> copy;
    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        copy = groupedPackets;
    }

    // Соберём все элементы в vector, чтобы обратиться к последним N
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
            groupedPackets[key] = groupInfo; // всегда обновляем
            if (!selectedAdapterIp.empty()) {
                adapterPackets[selectedAdapterIp] = groupedPackets;
            }
        }
        // Не вызывай UpdateGroupedPackets здесь!
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
    items.reserve(7); // Резервируем место для 7 элементов

    // Добавляем элементы в правильном порядке
    items.push_back(info.direction == PacketDirection::Incoming ? L"Входящий" : L"Исходящий");  // 0
    items.push_back(StringToWString(info.sourceIp));                                            // 1
    items.push_back(std::to_wstring(info.sourcePort));                                         // 2
    items.push_back(StringToWString(info.destIp));                                             // 3
    items.push_back(std::to_wstring(info.destPort));                                           // 4
    items.push_back(StringToWString(info.protocol));                                           // 5
    items.push_back(std::to_wstring(info.processId)); 									   // 6
    items.push_back(StringToWString(info.processName));                                        // 7

/*
    // Отладочный вывод
    wchar_t debug[512];
    swprintf_s(debug, L"Adding packet: Dir=%s, SrcIP=%s, SrcPort=%d, DstIP=%s, DstPort=%d, Proto=%s, Proc=%s\n",
        items[0].c_str(), items[1].c_str(), info.sourcePort,
        items[3].c_str(), info.destPort, items[5].c_str(), items[6].c_str());
    OutputDebugString(debug);
*/
    int index = connectionsListView.AddItem(items);
    if (index < 0) {
        OutputDebugString(L"Failed to add item to ListView!\n");
        return;
    }

    ListView_EnsureVisible(connectionsListView.GetHandle(), index, FALSE);
}

// Управление захватом
void MainWindow::StartCapture() {
    // Проверяем только наличие выбранного адаптера
    if (selectedAdapterIp.empty()) {
        MessageBox(hwnd, L"Please select a network adapter first", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    OutputDebugString((L"Starting capture on adapter: " +
        StringToWString(selectedAdapterIp) + L"\n").c_str());

    packetInterceptor.SetCurrentAdapter(selectedAdapterIp);
    if (packetInterceptor.StartCapture(selectedAdapterIp)) {
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
    // Проверяем состояние захвата
    if (!packetInterceptor.IsCapturing()) return;

    packetInterceptor.StopCapture();
    isCapturing = false;
    EnableWindow(GetDlgItem(hwnd, ID_START_CAPTURE), TRUE);
    EnableWindow(GetDlgItem(hwnd, ID_STOP_CAPTURE), FALSE);

    AddSystemMessage(L"Stopped capturing");
    OutputDebugString(L"Stopped capture\n");
}

// Вспомогательные методы
// Добавляем реализацию AddSystemMessage
void MainWindow::AddSystemMessage(const std::wstring& message) {
    if (connectionsListView.GetHandle()) {
        std::vector<std::wstring> items = { message };
        connectionsListView.AddItem(items);
    }
}

void MainWindow::OnAdapterSelected() {
    // Сохраняем текущий список под старым ключом
    if (!selectedAdapterIp.empty()) {
        adapterPackets[selectedAdapterIp] = groupedPackets;
    }

    HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
    int selectedIndex = SendMessage(comboBox, CB_GETCURSEL, 0, 0);

    if (selectedIndex != CB_ERR) {
        auto adapters = packetInterceptor.GetAdapters();
        if (selectedIndex < static_cast<int>(adapters.size())) {
            selectedAdapterIp = adapters[selectedIndex].address;
            UpdateAdapterInfo();

            // Всегда пробуем загрузить список с диска для выбранного адаптера
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

        case WM_APP + 1: // Наше пользовательское сообщение для инициализации
        {
            // Автоматически выбираем первый адаптер
            auto adapters = window->packetInterceptor.GetAdapters();
            if (!adapters.empty()) {
                HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
                SendMessage(comboBox, CB_SETCURSEL, 0, 0);
                window->selectedAdapterIp = adapters[0].address;
                window->UpdateAdapterInfo();
                EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
                // PATCH: load packets for auto-selected adapter
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
        case WM_APP + 2:
        {
            OutputDebugStringA("WM_APP+2 received\n");
            PacketInfo* packet = (PacketInfo*)lParam;
            if (packet) {
                window->OnPacketCaptured(*packet);
                delete packet;
            }
            return 0;
        }
        case WM_COMMAND:
        {
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
                    return 0;  // Обработали сообщение
                }
                break;

            case IDC_STOP_CAPTURE:
                if (wmEvent == BN_CLICKED) {
                    window->OnStopCapture();
                    return 0;  // Обработали сообщение
                }
                break;

            case IDC_ADAPTER_COMBO:
                if (wmEvent == CBN_SELCHANGE) {
                    window->OnAdapterSelected();
                    return 0;  // Обработали сообщение
                }
                break;
            }

            // Если не обработали команду, передаем дальше
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



// Публичные методы
void MainWindow::Show(int nCmdShow) {
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    if (packetInterceptor.Initialize()) {
        auto adapters = packetInterceptor.GetNetworkAdapters();

        if (!adapters.empty()) {
            if (selectedAdapterIp.empty()) {
                AutoSelectAdapter();
            }
            UpdateAdapterInfo();
        }
    }
}


void MainWindow::UpdateRulesList() {
    // TODO: Обновить список правил
}

void MainWindow::UpdateConnectionsList() {
    // TODO: Обновить список соединений
}

void MainWindow::AddRule() {
    // TODO: Добавить реализацию
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