#define WIN32_LEAN_AND_MEAN
#include "main_window.h"
#include <commctrl.h>
#include <windowsx.h>
#include <ctime>
#include <vector>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")
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

std::string MainWindow::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }

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

// Новый способ: только добавляем новые пакеты в ListView, не очищая его каждый раз.
// Для хранения порядка последних N групп используем std::deque
struct GroupedPacketView {
    std::deque<std::string> order; // ключи (groupKey) в порядке добавления
    std::map<std::string, GroupedPacketInfo> groups;
};

GroupedPacketView groupedPacketView;

void MainWindow::ProcessPacketBatch() {
    std::vector<PacketInfo> toDisplay;
    {
        std::lock_guard<std::mutex> lock(packetMutex);
        while (!packetQueue.empty()) {
            toDisplay.push_back(packetQueue.front());
            packetQueue.pop_front();
        }
    }

    bool needUpdate = false;
    for (const auto& pkt : toDisplay) {
        needUpdate |= OnPacketCaptured(pkt);
    }

    if (needUpdate) {
        UpdateGroupedPacketsNoDuplicates();
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



// Новый метод: добавлять только новые элементы
void MainWindow::UpdateGroupedPacketsIncremental() {
    std::deque<std::string> orderCopy;
    std::map<std::string, GroupedPacketInfo> groupsCopy;
    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        orderCopy = groupedPacketView.order;
        groupsCopy = groupedPackets;
    }

    // Определяем сколько уже отрисовано строк
    size_t listCount = connectionsListView.GetItemCount();
    size_t total = orderCopy.size();
    size_t start = (total > MAX_DISPLAYED_PACKETS) ? total - MAX_DISPLAYED_PACKETS : 0;

    // Если полностью сбились с синхронизации — перерисовываем весь список
    if (listCount > (total - start) + 10) {
        // слишком много лишнего, делаем полный сброс
        connectionsListView.SetRedraw(false);
        connectionsListView.Clear();
        listCount = 0;
        connectionsListView.SetRedraw(true);
    }

    // Добавляем только новые строки (уникальные ключи)
    for (size_t i = listCount + start; i < total; ++i) {
        const std::string& key = orderCopy[i];
        auto it = groupsCopy.find(key);
        if (it == groupsCopy.end())
            continue;
        const auto& packet = it->second;
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
    // Лимитируем длину списка
    while (connectionsListView.GetItemCount() > MAX_DISPLAYED_PACKETS) {
        connectionsListView.DeleteItem(0);
    }
    InvalidateRect(connectionsListView.GetHandle(), NULL, FALSE);
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

    // После загрузки сбрасываем порядок
    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        groupedPacketView.order.clear();
        for (const auto& pair : loaded) {
            groupedPacketView.order.push_back(pair.first);
        }
    }
}

void MainWindow::UpdateGroupedPacketsNoDuplicates() {
    // Сохраняем текущую позицию скролла
    int topIndex = ListView_GetTopIndex(connectionsListView.GetHandle());

    connectionsListView.SetRedraw(false);

    std::deque<std::string> orderCopy;
    std::map<std::string, GroupedPacketInfo> groupsCopy;
    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        orderCopy = groupedPacketView.order;
        groupsCopy = groupedPackets;
    }

    // Проверяем только новые ключи
    std::set<std::string> newKeys;
    for (const auto& key : orderCopy) {
        if (displayedKeys.find(key) == displayedKeys.end()) {
            newKeys.insert(key);
        }
    }

    // Если есть новые ключи, обновляем весь список
    if (!newKeys.empty()) {
        connectionsListView.Clear();
        displayedKeys.clear();

        size_t total = orderCopy.size();
        size_t start = (total > MAX_DISPLAYED_PACKETS) ? total - MAX_DISPLAYED_PACKETS : 0;

        for (size_t i = start; i < total; ++i) {
            const std::string& key = orderCopy[i];
            auto it = groupsCopy.find(key);
            if (it == groupsCopy.end())
                continue;

            const auto& packet = it->second;
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
            displayedKeys.insert(key);
        }
    }

    connectionsListView.SetRedraw(true);

    // Восстанавливаем позицию скролла
    if (topIndex > 0) {
        ListView_EnsureVisible(connectionsListView.GetHandle(), topIndex, FALSE);
    }
    InvalidateRect(connectionsListView.GetHandle(), NULL, FALSE);
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
         this->PushPacket(packet);
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




// Старый метод можно оставить для случаев полной перезагрузки списка
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

bool MainWindow::OnPacketCaptured(const PacketInfo& packet) {
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
        bool isNewPacket = false;

        {
            std::lock_guard<std::mutex> lock(groupedPacketsMutex);
            // Добавляем только если такого ключа ещё не было
            if (groupedPackets.find(key) == groupedPackets.end()) {
                isNewPacket = true;
                groupedPacketView.order.push_back(key);
                if (groupedPacketView.order.size() > MAX_DISPLAYED_PACKETS) {
                    std::string toRemove = groupedPacketView.order.front();
                    groupedPacketView.order.pop_front();
                    groupedPackets.erase(toRemove);
                    displayedKeys.erase(toRemove);
                }
            }
            groupedPackets[key] = groupInfo;
            if (!selectedAdapterIp.empty()) {
                adapterPackets[selectedAdapterIp] = groupedPackets;
            }
        }

        return isNewPacket;
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("OnPacketCaptured error: " + std::string(e.what()) + "\n").c_str());
        return false;
    }
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

std::string MainWindow::GetPacketKeyFromListView(int index) {
    if (index < 0) {
        OutputDebugStringA("Invalid index in GetPacketKeyFromListView\n");
        return "";
    }

    wchar_t sourceIp[256] = { 0 };
    wchar_t destIp[256] = { 0 };
    wchar_t protocol[32] = { 0 };
    wchar_t processName[256] = { 0 };
    wchar_t direction[32] = { 0 };

    ListView_GetItemText(connectionsListView.GetHandle(), index, 0, direction, 32);
    ListView_GetItemText(connectionsListView.GetHandle(), index, 1, sourceIp, 256);
    ListView_GetItemText(connectionsListView.GetHandle(), index, 3, destIp, 256);
    ListView_GetItemText(connectionsListView.GetHandle(), index, 5, protocol, 32);
    ListView_GetItemText(connectionsListView.GetHandle(), index, 7, processName, 256);

    // Отладочный вывод
    OutputDebugStringW(L"ListView data:\n");
    OutputDebugStringW(L"Direction: "); OutputDebugStringW(direction); OutputDebugStringW(L"\n");
    OutputDebugStringW(L"Source IP: "); OutputDebugStringW(sourceIp); OutputDebugStringW(L"\n");
    OutputDebugStringW(L"Dest IP: "); OutputDebugStringW(destIp); OutputDebugStringW(L"\n");

    GroupedPacketInfo tempInfo;
    tempInfo.sourceIp = WStringToString(sourceIp);
    tempInfo.destIp = WStringToString(destIp);
    tempInfo.protocol = WStringToString(protocol);
    tempInfo.processName = WStringToString(processName);
    tempInfo.direction = (wcscmp(direction, L"Входящий") == 0) ?
        PacketDirection::Incoming : PacketDirection::Outgoing;

    wchar_t portStr[32];
    ListView_GetItemText(connectionsListView.GetHandle(), index, 2, portStr, 32);
    tempInfo.sourcePort = static_cast<uint16_t>(_wtoi(portStr));

    ListView_GetItemText(connectionsListView.GetHandle(), index, 4, portStr, 32);
    tempInfo.destPort = static_cast<uint16_t>(_wtoi(portStr));

    wchar_t pidStr[32];
    ListView_GetItemText(connectionsListView.GetHandle(), index, 6, pidStr, 32);
    tempInfo.processId = static_cast<uint32_t>(_wtoi(pidStr));

    std::string key = tempInfo.GetKey();
    OutputDebugStringA(("Generated key: " + key + "\n").c_str());
    return key;
}

std::shared_ptr<GroupedPacketInfo> MainWindow::GetPacketInfo(const std::string& key) {
    std::lock_guard<std::mutex> lock(groupedPacketsMutex);
    auto it = groupedPackets.find(key);
    if (it != groupedPackets.end()) {
        return std::make_shared<GroupedPacketInfo>(it->second);
    }
    return nullptr;
}

void MainWindow::CopyTextToClipboard(const std::string& text) {
    if (text.empty()) return;

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        size_t len = text.length() + 1;
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
        if (hMem) {
            memcpy(GlobalLock(hMem), text.c_str(), len);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void MainWindow::AddBlockingRule(const std::string& ip) {
    // TODO: Реализовать добавление правила блокировки
    // Например, через Windows Firewall API
    MessageBox(hwnd, StringToWString(
        "Блокировка IP " + ip + " (требуется реализация)").c_str(),
        L"Информация", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::OnPacketCommand(WPARAM wParam) {
    int selectedIndex = ListView_GetNextItem(connectionsListView.GetHandle(), -1, LVNI_SELECTED);
    if (selectedIndex == -1)
        return;

    std::string key = GetPacketKeyFromListView(selectedIndex);
    if (key.empty())
        return;

    auto packet = GetPacketInfo(key);
    if (!packet)
        return;

    switch (LOWORD(wParam)) {
    case CMD_PACKET_PROPERTIES: {
        OutputDebugStringA("Opening properties dialog...\n");
        DialogBoxParam(
            GetModuleHandle(NULL),
            MAKEINTRESOURCE(IDD_PACKET_PROPERTIES),
            hwnd,
            PacketPropertiesDialogProc,
            reinterpret_cast<LPARAM>(packet.get())
        );
        break;
    }

    case CMD_COPY_SOURCE_IP: {
        OutputDebugStringA(("Copying source IP: " + packet->sourceIp + "\n").c_str());
        if (!packet->sourceIp.empty()) {
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = packet->sourceIp.length() + 1;
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) {
                    memcpy(GlobalLock(hMem), packet->sourceIp.c_str(), len);
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
                CloseClipboard();
            }
        }
        break;
    }

    case CMD_COPY_DEST_IP: {
        OutputDebugStringA(("Copying dest IP: " + packet->destIp + "\n").c_str());
        if (!packet->destIp.empty()) {
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                size_t len = packet->destIp.length() + 1;
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
                if (hMem) {
                    memcpy(GlobalLock(hMem), packet->destIp.c_str(), len);
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
                CloseClipboard();
            }
        }
        break;
    }
    case CMD_BLOCK_IP: {
        std::wstring msg = L"Заблокировать IP " + StringToWString(packet->sourceIp) + L"?";
        if (MessageBox(hwnd, msg.c_str(), L"Подтверждение", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            AddBlockingRule(packet->sourceIp);
        }
        break;
    }

    case CMD_WHOIS_IP: {
        std::wstring url = L"https://whois.domaintools.com/" + StringToWString(packet->sourceIp);
        ShellExecute(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        break;
    }
    }
}

void MainWindow::OnContextMenu(HWND hwnd, int x, int y) {
    if (hwnd != connectionsListView.GetHandle())
        return;

    // Получаем выбранный индекс
    int selectedIndex = ListView_GetNextItem(connectionsListView.GetHandle(), -1, LVNI_SELECTED);
    if (selectedIndex == -1)
        return;

    POINT pt = { x, y };
    if (x == -1 && y == -1) {
        RECT rc;
        ListView_GetItemRect(hwnd, selectedIndex, &rc, LVIR_BOUNDS);
        pt.x = rc.left;
        pt.y = rc.bottom;
        ClientToScreen(hwnd, &pt);
    }

    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, CMD_PACKET_PROPERTIES, L"Свойства");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, CMD_COPY_SOURCE_IP, L"Копировать IP источника");
    AppendMenu(hMenu, MF_STRING, CMD_COPY_DEST_IP, L"Копировать IP назначения");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, CMD_BLOCK_IP, L"Заблокировать IP");
    AppendMenu(hMenu, MF_STRING, CMD_WHOIS_IP, L"Whois для IP");

    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

void MainWindow::ShowPacketProperties(int itemIndex) {
    std::string key = GetPacketKeyFromListView(itemIndex);
    if (key.empty()) return;

    auto packet = GetPacketInfo(key);
    if (!packet) return;

    DialogBoxParam(hInstance,
        MAKEINTRESOURCE(IDD_PACKET_PROPERTIES),
        hwnd,
        PacketPropertiesDialogProc,
        reinterpret_cast<LPARAM>(&packet));
}

void MainWindow::OnAdapterSelected() {
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
            // Сбросить порядок после смены адаптера!
            // После загрузки адаптера:
            {
                std::lock_guard<std::mutex> lock(groupedPacketsMutex);
                groupedPacketView.order.clear();
                displayedKeys.clear(); // Очищаем отслеживание
                for (const auto& pair : groupedPackets) {
                    groupedPacketView.order.push_back(pair.first);
                }
            }
            UpdateGroupedPacketsNoDuplicates();
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
        case WM_CONTEXTMENU: {
            window->OnContextMenu((HWND)wParam, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        }
        case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);
            if (LOWORD(wParam) >= CMD_PACKET_PROPERTIES &&
                LOWORD(wParam) <= CMD_WHOIS_IP) {
                window->OnPacketCommand(wParam);
                return 0;
            }
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
            break;
        }
        case WM_TIMER:
            if (wParam == 1) {
                window->ProcessPacketBatch();
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

INT_PTR CALLBACK MainWindow::PacketPropertiesDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        // Получаем указатель на пакет из lParam
        GroupedPacketInfo* packet = reinterpret_cast<GroupedPacketInfo*>(lParam);
        if (!packet) return FALSE;

        // Заполняем поля диалога
        SetDlgItemText(hwnd, IDC_SOURCE,
            (StringToWString(packet->sourceIp) + L":" +
                std::to_wstring(packet->sourcePort)).c_str());

        SetDlgItemText(hwnd, IDC_DEST,
            (StringToWString(packet->destIp) + L":" +
                std::to_wstring(packet->destPort)).c_str());

        SetDlgItemText(hwnd, IDC_PROTOCOL,
            StringToWString(packet->protocol).c_str());

        SetDlgItemText(hwnd, IDC_PID,
            std::to_wstring(packet->processId).c_str());

        SetDlgItemText(hwnd, IDC_PROCESS_NAME,
            StringToWString(packet->processName).c_str());

        // Сохраняем указатель на пакет для использования в других обработчиках
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(packet));
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            EndDialog(hwnd, LOWORD(wParam));
            return TRUE;

        /*case IDC_BLOCK_IP: {
            auto packet = reinterpret_cast<GroupedPacketInfo*>(
                GetWindowLongPtr(hwnd, GWLP_USERDATA));
            if (packet) {
                std::wstring msg = L"Заблокировать IP " +
                    StringToWString(packet->sourceIp) + L"?";
                if (MessageBox(hwnd, msg.c_str(), L"Подтверждение",
                    MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    AddBlockingRule(packet->sourceIp);
                }
            }
            return TRUE;
        }*/
        }
        break;
    }
    return FALSE;
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