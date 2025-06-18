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
#include <chrono>
#include <psapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <tlhelp32.h>
#include "rule_manager.h"


#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

void MainWindow::OpenRulesDialog() {
    RuleManager::Instance().ShowRulesDialog(hwnd);
}

// Проверка, что процесс уже запущен
bool IsBlockerRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry = { sizeof(entry) };
    bool found = false;
    if (Process32FirstW(hSnapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"FirewallDaemon.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &entry));
    }
    CloseHandle(hSnapshot);
    return found;
}

std::wstring GetMyExecutableDir()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring exePath(path);
    size_t pos = exePath.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        exePath = exePath.substr(0, pos);

    // Отладочное сообщение
    std::wstring debugMsg = L"[DEBUG] GetMyExecutableDir: exe path = ";
    debugMsg += path;
    debugMsg += L", dir = ";
    debugMsg += exePath;
    OutputDebugStringW(debugMsg.c_str());
    OutputDebugStringW(L"\n");
    return exePath;
}
std::wstring GetDaemonPath()
{
    std::wstring exeDir = GetMyExecutableDir();
    std::wstring daemonPath = exeDir + L"\\FirewallDaemon.exe";
    std::wstring debugMsg = L"[DEBUG] GetDaemonPath: ";
    debugMsg += daemonPath;
    OutputDebugStringW(debugMsg.c_str());
    OutputDebugStringW(L"\n");
    return daemonPath;
}
// Запуск процесса-блокировщика
void StartBlockerProcess()
{
    std::wstring daemonPath = GetDaemonPath();
    if (daemonPath.empty()) return; // Не найден

    if (IsBlockerRunning()) return;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(daemonPath.c_str(), NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
// Остановка процесса по имени
void StopBlockerProcess() {
    // 1. Открываем Event для сигнала остановки
    HANDLE hStopEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\FirewallDaemonStopEvent");
    if (hStopEvent) {
        OutputDebugStringW(L"[DEBUG] StopBlockerProcess: Sending stop event to daemon...\n");
        SetEvent(hStopEvent); // Сигнал демону корректно завершиться
        CloseHandle(hStopEvent);
    }
    else {
        OutputDebugStringW(L"[DEBUG] StopBlockerProcess: Stop event not found (daemon not running?)\n");
        return;
    }

    // 2. (Опционально) ждем завершения процесса демона — ищем его по имени
    bool processFound = false;
    DWORD daemonPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(hSnapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, L"FirewallDaemon.exe") == 0) {
                    processFound = true;
                    daemonPid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &entry));
        }
        CloseHandle(hSnapshot);
    }
}

std::string GetDomainByIp(const std::string& ip) {
    if (ip.empty() || ip == "Unknown") return "";
    char host[NI_MAXHOST] = { 0 };
    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    sa.sin_port = 0;
    int res = getnameinfo((sockaddr*)&sa, sizeof(sa), host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
    return (res == 0) ? std::string(host) : "";
}

std::string TimeTToString(const time_t& time) {
    std::ostringstream oss;
    tm tmTime;
    localtime_s(&tmTime, &time);
    oss << std::put_time(&tmTime, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string GetCurrentUTCTime() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc;
    gmtime_s(&tm_utc, &now_c);

    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string GetLocalSystemTime() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::string(buffer);
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
    StartBlockerProcess();
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

// Добавим функцию получения пути процесса
std::string MainWindow::GetProcessPath(DWORD processId) {
    if (processId == 0) return "";

    // Открываем процесс с расширенными правами
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId);

    if (!hProcess) {
        // Пробуем открыть с ограниченными правами
        hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            processId);
    }

    if (hProcess) {
        WCHAR path[MAX_PATH] = { 0 };
        DWORD size = MAX_PATH;

        // Пробуем разные способы получить путь
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            return WStringToString(path);
        }
        else {
            // Альтернативный метод
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                if (GetModuleFileNameEx(hProcess, hMod, path, MAX_PATH)) {
                    CloseHandle(hProcess);
                    return WStringToString(path);
                }
            }
        }
        CloseHandle(hProcess);
    }

    // Если не удалось получить путь стандартными методами,
    // пробуем через WMI
    try {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr)) {
            IWbemLocator* pLoc = NULL;
            hr = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator,
                (LPVOID*)&pLoc);

            if (SUCCEEDED(hr)) {
                IWbemServices* pSvc = NULL;
                hr = pLoc->ConnectServer(
                    _bstr_t(L"ROOT\\CIMV2"),
                    NULL, NULL, NULL,
                    0, NULL, NULL,
                    &pSvc);

                if (SUCCEEDED(hr)) {
                    hr = CoSetProxyBlanket(
                        pSvc,
                        RPC_C_AUTHN_WINNT,
                        RPC_C_AUTHZ_NONE,
                        NULL,
                        RPC_C_AUTHN_LEVEL_CALL,
                        RPC_C_IMP_LEVEL_IMPERSONATE,
                        NULL,
                        EOAC_NONE);

                    if (SUCCEEDED(hr)) {
                        std::wstring query = L"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " +
                            std::to_wstring(processId);
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hr = pSvc->ExecQuery(
                            bstr_t("WQL"),
                            bstr_t(query.c_str()),
                            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                            NULL,
                            &pEnumerator);

                        if (SUCCEEDED(hr)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;

                            while (pEnumerator) {
                                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                                if (uReturn == 0) break;

                                VARIANT vtProp;
                                hr = pclsObj->Get(L"ExecutablePath", 0, &vtProp, 0, 0);
                                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                                    std::wstring path = vtProp.bstrVal;
                                    VariantClear(&vtProp);
                                    pclsObj->Release();
                                    pEnumerator->Release();
                                    pSvc->Release();
                                    pLoc->Release();
                                    CoUninitialize();
                                    return WStringToString(path);
                                }
                                VariantClear(&vtProp);
                                pclsObj->Release();
                            }
                            pEnumerator->Release();
                        }
                    }
                    pSvc->Release();
                }
                pLoc->Release();
            }
            CoUninitialize();
        }
    }
    catch (...) {
        // Игнорируем ошибки WMI
    }

    return "";
}

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
        HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
        SendMessage(comboBox, CB_SETCURSEL, 0, 0);
        UpdateAdapterInfo();
    }

    // Инициализируем адаптер сразу после создания окна
    PostMessage(hwnd, WM_APP + 1, 0, 0); // Отправляем пользовательское сообщение для инициализации

    return true;
}

// Статическая функция форматирования размера файла
std::wstring MainWindow::FormatFileSize(size_t bytes) {
    const wchar_t* sizes[] = { L"Б", L"КБ", L"МБ", L"ГБ" };
    int order = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024 && order < 3) {
        order++;
        size = size / 1024;
    }

    wchar_t buffer[64];
    if (order == 0) {
        swprintf_s(buffer, L"%d %s", static_cast<int>(size), sizes[order]);
    }
    else {
        swprintf_s(buffer, L"%.2f %s", size, sizes[order]);
    }
    return buffer;
}




void MainWindow::SaveAdapterPackets(const std::string& adapter) {
    if (adapter.empty()) {
        FirewallLogger::Instance().LogServiceEvent(
            FirewallEventType::SERVICE_ERROR,
            "Failed to save packets: No adapter selected"
        );
        MessageBox(hwnd, L"Адаптер не выбран!", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    if (groupedPackets.empty()) {
        FirewallLogger::Instance().LogServiceEvent(
            FirewallEventType::SERVICE_ERROR,
            "Failed to save packets: No packets to save for adapter: " + adapter
        );
        MessageBox(hwnd, L"Нет ни одного пакета для сохранения!", L"Инфо", MB_OK | MB_ICONINFORMATION);
        return;
    }

    char buf[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buf);
    std::string filename = "packets_" + adapter + ".csv";
    std::ofstream fout(filename, std::ios::trunc);

    if (!fout) {
        FirewallLogger::Instance().LogServiceEvent(
            FirewallEventType::SERVICE_ERROR,
            "Failed to create file: " + filename + " in directory: " + buf
        );
        MessageBox(hwnd, L"Не удалось создать файл!", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    size_t packetCount = groupedPackets.size();

    for (const auto& pair : groupedPackets) {
        const auto& pkt = pair.second;
        fout << pkt.time << ','
            << pkt.sourceIp << ','
            << pkt.destIp << ','
            << pkt.protocol << ','
            << pkt.processName << ','
            << pkt.totalSize << ','
            << pkt.packetCount << ','
            << pkt.processId << ','
            << pkt.sourcePort << ','
            << pkt.destPort << ','
            << (pkt.direction == PacketDirection::Incoming ? "in" : "out") << '\n';
    }
    fout.close();

    std::stringstream details;
    details << "Saved packets to file\n"
        << "Adapter: " << adapter << "\n"
        << "File path: " << buf << "\\" << filename << "\n"
        << "Total packets saved: " << packetCount;

    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::PACKETS_SAVED,
        details.str()
    );

    MessageBox(hwnd, L"Список успешно сохранён!", L"Инфо", MB_OK | MB_ICONINFORMATION);
}

void MainWindow::LoadAdapterPackets(const std::string& adapter) {
    OutputDebugStringA(("Loading packets for adapter: " + adapter + "\n").c_str());

    std::string filename = "packets_" + adapter + ".csv";
    std::ifstream fin(filename);
    if (!fin) {
        OutputDebugStringA(("Failed to open file: " + filename + "\n").c_str());
        return;
    }

    std::map<std::string, GroupedPacketInfo> loaded;
    std::string line;
    size_t lineCount = 0;

    // Пропускаем заголовок если он есть
    std::getline(fin, line);

    while (std::getline(fin, line)) {
        try {
            std::stringstream ss(line);
            GroupedPacketInfo pkt;

            std::getline(ss, pkt.time, ',');
            std::getline(ss, pkt.sourceIp, ',');
            std::getline(ss, pkt.destIp, ',');
            std::getline(ss, pkt.protocol, ',');
            std::getline(ss, pkt.processName, ',');

            std::string temp;
            std::getline(ss, temp, ','); // totalSize
            pkt.totalSize = std::stoull(temp);

            std::getline(ss, temp, ','); // packetCount
            pkt.packetCount = std::stoul(temp);

            std::getline(ss, temp, ','); // processId
            pkt.processId = static_cast<uint32_t>(std::stoul(temp));

            std::getline(ss, temp, ','); // sourcePort
            pkt.sourcePort = static_cast<uint16_t>(std::stoi(temp));

            std::getline(ss, temp, ','); // destPort
            pkt.destPort = static_cast<uint16_t>(std::stoi(temp));

            std::getline(ss, temp, ','); // direction
            pkt.direction = (temp == "in") ? PacketDirection::Incoming : PacketDirection::Outgoing;

            std::string key = pkt.GetKey();
            loaded[key] = pkt;
            lineCount++;

            OutputDebugStringA(("Loaded packet: " + key +
                "\nProcess: " + pkt.processName +
                "\nProtocol: " + pkt.protocol +
                "\nCount: " + std::to_string(pkt.packetCount) + "\n").c_str());
        }
        catch (const std::exception& e) {
            OutputDebugStringA(("Error parsing line: " + line + "\nError: " + e.what() + "\n").c_str());
        }
    }
    fin.close();

    // Собираем статистику по загруженным пакетам
    std::map<std::string, size_t> processStats;
    std::map<std::string, size_t> protocolStats;
    size_t totalPackets = 0;
    for (const auto& pair : loaded) {
        processStats[pair.second.processName] += pair.second.packetCount;
        protocolStats[pair.second.protocol] += pair.second.packetCount;
        totalPackets += pair.second.packetCount;
    }

    // Логируем статистику
    std::stringstream stats;
    stats << "Loaded packets statistics:\n"
        << "Total groups: " << loaded.size() << "\n"
        << "Total packets: " << totalPackets << "\n"
        << "\nBy process:\n";
    for (const auto& proc : processStats) {
        stats << " - " << proc.first << ": " << proc.second << " packets\n";
    }
    stats << "\nBy protocol:\n";
    for (const auto& proto : protocolStats) {
        stats << " - " << proto.first << ": " << proto.second << " packets\n";
    }
    OutputDebugStringA(stats.str().c_str());

    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);
        // Сохраняем в глобальный map адаптеров
        adapterPackets[adapter] = loaded;

        // Обновляем текущие пакеты
        groupedPackets = loaded;

        // Очищаем и обновляем порядок отображения
        groupedPacketView.order.clear();
        displayedKeys.clear();

        // Создаем вектор для сортировки
        std::vector<std::pair<std::string, std::string>> sortedKeys; // key, time
        for (const auto& pair : loaded) {
            sortedKeys.push_back({ pair.first, pair.second.time });
        }

        // Сортируем по времени
        std::sort(sortedKeys.begin(), sortedKeys.end(),
            [](const auto& a, const auto& b) {
                return a.second < b.second;
            });

        // Обновляем порядок
        for (const auto& pair : sortedKeys) {
            groupedPacketView.order.push_back(pair.first);
        }

        OutputDebugStringA(("Order updated with " +
            std::to_string(groupedPacketView.order.size()) + " items\n").c_str());
    }

    // Обновляем отображение
    UpdateGroupedPacketsNoDuplicates();

    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::PACKETS_LOADED,
        stats.str()
    );
}

void MainWindow::UpdateGroupedPacketsNoDuplicates() {
    OutputDebugStringA("\n=== Starting UpdateGroupedPacketsNoDuplicates ===\n");
    OutputDebugStringA(("Current adapter: " + selectedAdapterIp + "\n").c_str());

    // Сохраняем текущую позицию скролла
    int topIndex = ListView_GetTopIndex(connectionsListView.GetHandle());

    connectionsListView.SetRedraw(false);

    std::deque<std::string> orderCopy;
    std::map<std::string, GroupedPacketInfo> groupsCopy;

    {
        std::lock_guard<std::mutex> lock(groupedPacketsMutex);

        // Убеждаемся, что у нас есть выбранный адаптер
        if (!selectedAdapterIp.empty()) {
            // Получаем пакеты только для текущего адаптера
            auto adapterIt = adapterPackets.find(selectedAdapterIp);
            if (adapterIt != adapterPackets.end()) {
                groupsCopy = adapterIt->second;

                // Обновляем текущие пакеты для выбранного адаптера
                groupedPackets = groupsCopy;

                OutputDebugStringA(("Loaded " + std::to_string(groupsCopy.size()) +
                    " packet groups for adapter " + selectedAdapterIp + "\n").c_str());
            }
            else {
                OutputDebugStringA("No packets found for current adapter\n");
                groupsCopy.clear();
                groupedPackets.clear();
            }
        }
        else {
            OutputDebugStringA("No adapter selected\n");
            groupsCopy.clear();
            groupedPackets.clear();
        }

        orderCopy = groupedPacketView.order;
    }

    // Проверяем только новые ключи
    std::set<std::string> newKeys;
    for (const auto& key : orderCopy) {
        if (displayedKeys.find(key) == displayedKeys.end()) {
            newKeys.insert(key);
            OutputDebugStringA(("New key found: " + key + "\n").c_str());
        }
    }

    // Если есть новые ключи, обновляем весь список
    if (!newKeys.empty()) {
        OutputDebugStringA(("Updating list view with " +
            std::to_string(newKeys.size()) + " new packets\n").c_str());

        connectionsListView.Clear();
        displayedKeys.clear();

        size_t total = orderCopy.size();
        size_t start = (total > MAX_DISPLAYED_PACKETS) ? total - MAX_DISPLAYED_PACKETS : 0;

        size_t displayed = 0;
        size_t filtered = 0;

        for (size_t i = start; i < total; ++i) {
            const std::string& key = orderCopy[i];
            auto it = groupsCopy.find(key);
            if (it == groupsCopy.end()) {
                OutputDebugStringA(("Key not found in groups: " + key + "\n").c_str());
                continue;
            }

            const auto& packet = it->second;

            // Отладочная информация
            std::stringstream debugInfo;
            debugInfo << "Processing packet:\n"
                << "Protocol: " << packet.protocol << "\n"
                << "Process: " << packet.processName << "\n"
                << "Source: " << packet.sourceIp << ":" << packet.sourcePort << "\n"
                << "Dest: " << packet.destIp << ":" << packet.destPort << "\n"
                << "Count: " << packet.packetCount << "\n";
            OutputDebugStringA(debugInfo.str().c_str());

            // Фильтрация по протоколу
            bool filtered_out = false;
            switch (settings.protocolFilter) {
            case ProtocolFilter::All:
                break;
            case ProtocolFilter::TCP_UDP:
                if (packet.protocol != "TCP" && packet.protocol != "UDP") {
                    filtered_out = true;
                }
                break;
            case ProtocolFilter::TCP:
                if (packet.protocol != "TCP") {
                    filtered_out = true;
                }
                break;
            case ProtocolFilter::UDP:
                if (packet.protocol != "UDP") {
                    filtered_out = true;
                }
                break;
            }

            if (filtered_out) {
                filtered++;
                OutputDebugStringA("Packet filtered out by protocol\n");
                continue;
            }

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
            displayed++;
        }

        OutputDebugStringA(("Update complete:\n"
            "Total groups: " + std::to_string(total) + "\n" +
            "Displayed: " + std::to_string(displayed) + "\n" +
            "Filtered: " + std::to_string(filtered) + "\n").c_str());
    }
    else {
        OutputDebugStringA("No new packets to display\n");
    }

    connectionsListView.SetRedraw(true);

    // Восстанавливаем позицию скролла
    if (topIndex > 0) {
        ListView_EnsureVisible(connectionsListView.GetHandle(), topIndex, FALSE);
    }

    InvalidateRect(connectionsListView.GetHandle(), NULL, FALSE);

    OutputDebugStringA("=== UpdateGroupedPacketsNoDuplicates completed ===\n\n");
}

void MainWindow::ClearSavedAdapterPackets(const std::string& adapter) {
    std::string filename = "packets_" + adapter + ".csv";
    std::remove(filename.c_str());

    size_t clearedPacketsCount = adapterPackets[adapter].size();
    adapterPackets[adapter].clear();

    if (adapter == selectedAdapterIp) {
        groupedPackets.clear();
        UpdateGroupedPackets();
    }

    std::stringstream details;
    details << "Cleared saved packets for adapter\n"
        << "Adapter: " << adapter << "\n"
        << "File removed: " << filename << "\n"
        << "Packets cleared: " << clearedPacketsCount;

    FirewallLogger::Instance().LogServiceEvent(
        FirewallEventType::PACKETS_CLEARED,
        details.str()
    );

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
     // Логируем начало захвата пакетов
     FirewallLogger::Instance().LogServiceEvent(
         FirewallEventType::CAPTURE_STARTED,
         "Started packet capture on adapter: " + selectedAdapterIp
     );
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
        // Сначала сохраняем текущие пакеты для адаптера
        if (!selectedAdapterIp.empty()) {
            std::lock_guard<std::mutex> lock(groupedPacketsMutex);
            adapterPackets[selectedAdapterIp] = groupedPackets;

            std::stringstream ss;
            ss << "Saving packets for adapter " << selectedAdapterIp << "\n"
                << "Total groups: " << groupedPackets.size() << "\n"
                << "Groups by process:\n";

            // Подсчитываем пакеты по процессам
            std::map<std::string, size_t> processCounts;
            for (const auto& pair : groupedPackets) {
                processCounts[pair.second.processName]++;
            }

            for (const auto& proc : processCounts) {
                ss << " - " << proc.first << ": " << proc.second << " groups\n";
            }

            FirewallLogger::Instance().LogServiceEvent(
                FirewallEventType::PACKETS_SAVED,
                ss.str()
            );
        }

        // Теперь останавливаем захват
        packetInterceptor.StopCapture();
        isCapturing = false;

        // Получаем количество пакетов из вашей структуры данных
        size_t packetCount = groupedPackets.size();

        FirewallLogger::Instance().LogServiceEvent(
            FirewallEventType::CAPTURE_STOPPED,
            "Stopped packet capture on adapter: " + selectedAdapterIp
        );

        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
        EnableWindow(GetDlgItem(hwnd, IDC_STOP_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_ADAPTER_COMBO), TRUE);

        AddSystemMessage(L"Capture stopped");

        // НЕ очищаем группы пакетов здесь
        // Обновляем отображение с текущими данными
        UpdateGroupedPacketsNoDuplicates();
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

    // Новый размер
    const int COMPACT_BUTTON_WIDTH = 80;
    const int COMPACT_BUTTON_HEIGHT = 22;
    const int COMPACT_MARGIN = 4;

    // Считаем позицию каждой кнопки компактно:
    int buttonX = MARGIN;
    auto add_btn = [&](LPCWSTR text, int id) {
        CreateWindowEx(
            0, WC_BUTTON, text,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            buttonX, buttonY, COMPACT_BUTTON_WIDTH, COMPACT_BUTTON_HEIGHT,
            hwnd, (HMENU)id, hInstance, NULL
        );
        buttonX += COMPACT_BUTTON_WIDTH + COMPACT_MARGIN;
        };

    add_btn(L"Старт", IDC_START_CAPTURE);
    add_btn(L"Стоп", IDC_STOP_CAPTURE);
    add_btn(L"Сохранить", IDC_SAVE_PACKETS);
    add_btn(L"Очистить", IDC_CLEAR_SAVED_PACKETS);
    add_btn(L"Правила", IDC_OPEN_RULES);
    add_btn(L"Настройки", IDC_OPEN_SETTINGS);

    // ComboBox размещаем справа
    HWND adapterCombo = CreateWindowEx(
        0, WC_COMBOBOX, L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        buttonX + COMPACT_MARGIN, buttonY, COMBO_WIDTH, COMBO_HEIGHT,
        hwnd, (HMENU)IDC_ADAPTER_COMBO, hInstance, NULL
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
    if (!rulesListView.Initialize(hwnd, 10, 40, 760, 200, (HMENU)IDC_RULES_LIST, hInstance)) {
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
        OutputDebugStringA(("OnPacketCaptured: proto=" + packet.protocol +
            " src=" + packet.sourceIp +
            " dst=" + packet.destIp +
            " sport=" + std::to_string(packet.sourcePort) +
            " dport=" + std::to_string(packet.destPort) + "\n").c_str());
        // Логируем пакет
        FirewallLogger::Instance().LogPacket(packet);
        GroupedPacketInfo groupInfo;
        groupInfo.sourceIp = packet.sourceIp;
        groupInfo.destIp = packet.destIp;
        groupInfo.protocol = packet.protocol;
        groupInfo.processId = packet.processId;
        groupInfo.processName = packet.processName;
        groupInfo.sourcePort = packet.sourcePort;
        groupInfo.destPort = packet.destPort;
        groupInfo.direction = packet.direction;
        groupInfo.processPath = GetProcessPath(packet.processId);

        // Инициализируем размер и счетчик для нового пакета
        groupInfo.totalSize = packet.size;
        groupInfo.packetCount = 1;

        std::string key = groupInfo.GetKey();
        bool isNewPacket = false;

        {
            std::lock_guard<std::mutex> lock(groupedPacketsMutex);
            auto it = groupedPackets.find(key);
            if (it == groupedPackets.end()) {
                // Новый уникальный пакет
                isNewPacket = true;
                groupInfo.time = GetLocalSystemTime();
                groupedPacketView.order.push_back(key);

                if (groupedPacketView.order.size() > MAX_DISPLAYED_PACKETS) {
                    std::string toRemove = groupedPacketView.order.front();
                    groupedPacketView.order.pop_front();
                    groupedPackets.erase(toRemove);
                    displayedKeys.erase(toRemove);
                }
            }
            else {
                // Обновляем существующий пакет
                groupInfo.time = it->second.time;
                groupInfo.processPath = it->second.processPath;
                groupInfo.totalSize = it->second.totalSize + packet.size;
                groupInfo.packetCount = it->second.packetCount + 1;
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
        EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), FALSE);
        EnableWindow(GetDlgItem(hwnd, IDC_STOP_CAPTURE), TRUE);

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
    EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
    EnableWindow(GetDlgItem(hwnd, IDC_STOP_CAPTURE), FALSE);

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

// Добавим вспомогательную функцию для копирования в буфер обмена
void MainWindow::CopyToClipboard(const std::string& text) {
    if (text.empty()) return;

    if (!OpenClipboard(hwnd)) return;

    EmptyClipboard();

    // Конвертируем в широкие символы для лучшей совместимости
    std::wstring wtext = StringToWString(text);
    size_t len = (wtext.length() + 1) * sizeof(wchar_t);

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (hMem) {
        wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
        if (pMem) {
            wcscpy_s(pMem, wtext.length() + 1, wtext.c_str());
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
    }

    CloseClipboard();
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
    if (selectedIndex == -1) return;

    // Получаем данные пакета напрямую из ListView
    wchar_t sourceIp[256] = { 0 };
    wchar_t destIp[256] = { 0 };

    ListView_GetItemText(connectionsListView.GetHandle(), selectedIndex, 1, sourceIp, 256);
    ListView_GetItemText(connectionsListView.GetHandle(), selectedIndex, 3, destIp, 256);

    std::string srcIp = WStringToString(sourceIp);
    std::string dstIp = WStringToString(destIp);

    switch (LOWORD(wParam)) {
    case CMD_PACKET_PROPERTIES: {
        std::string key = GetPacketKeyFromListView(selectedIndex);
        if (!key.empty()) {
            auto packet = GetPacketInfo(key);
            if (packet) {
                DialogBoxParam(
                    GetModuleHandle(NULL),
                    MAKEINTRESOURCE(IDD_PACKET_PROPERTIES),
                    hwnd,
                    PacketPropertiesDialogProc,
                    reinterpret_cast<LPARAM>(packet.get())
                );
            }
        }
        break;
    }

    case CMD_COPY_SOURCE_IP:
        CopyToClipboard(srcIp);
        break;

    case CMD_COPY_DEST_IP:
        CopyToClipboard(dstIp);
        break;

    case CMD_BLOCK_IP: {
        std::wstring msg = L"Заблокировать IP " + StringToWString(srcIp) + L"?";
        if (MessageBox(hwnd, msg.c_str(), L"Подтверждение",
            MB_YESNO | MB_ICONQUESTION) == IDYES) {
            AddBlockingRule(srcIp);
        }
        break;
    }

    case CMD_WHOIS_IP: {
        std::wstring url = L"https://whois.domaintools.com/" + StringToWString(srcIp);
        ShellExecute(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
        break;
    }
    }
}

void MainWindow::OnContextMenu(HWND hwnd, int x, int y) {
    if (hwnd != connectionsListView.GetHandle())
        return;

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
    if (!hMenu) return;

    AppendMenu(hMenu, MF_STRING, CMD_PACKET_PROPERTIES, L"Свойства");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, CMD_COPY_SOURCE_IP, L"Копировать IP источника");
    AppendMenu(hMenu, MF_STRING, CMD_COPY_DEST_IP, L"Копировать IP назначения");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, CMD_BLOCK_IP, L"Заблокировать IP");
    AppendMenu(hMenu, MF_STRING, CMD_WHOIS_IP, L"Whois для IP");

    // Важно: отправляем команды в главное окно
    TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        pt.x, pt.y, 0, this->hwnd, NULL);

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
    if (selectedAdapterIp.empty()) {
        return;
    }

    HWND comboBox = GetDlgItem(hwnd, IDC_ADAPTER_COMBO);
    int selectedIndex = SendMessage(comboBox, CB_GETCURSEL, 0, 0);

    if (selectedIndex != CB_ERR) {
        auto adapters = packetInterceptor.GetAdapters();
        if (selectedIndex < static_cast<int>(adapters.size())) {
            std::string previousAdapter = selectedAdapterIp;
            selectedAdapterIp = adapters[selectedIndex].address;

            // Логируем смену адаптера
            std::stringstream details;
            details << "Network adapter changed\n"
                << "Previous: " << (previousAdapter.empty() ? "none" : previousAdapter) << "\n"
                << "New: " << selectedAdapterIp;

            FirewallLogger::Instance().LogServiceEvent(
                FirewallEventType::ADAPTER_CHANGED,
                details.str()
            );

            // Очищаем текущие пакеты перед загрузкой новых
            {
                std::lock_guard<std::mutex> lock(groupedPacketsMutex);
                groupedPackets.clear();
                groupedPacketView.order.clear();
                displayedKeys.clear();
            }

            // Загружаем пакеты только для выбранного адаптера
            LoadAdapterPackets(selectedAdapterIp);

            UpdateAdapterInfo();
            EnableWindow(GetDlgItem(hwnd, IDC_START_CAPTURE), TRUE);
        }
    }
}

LRESULT CALLBACK MainWindow::MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window = nullptr;
    try {
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
                case IDC_SAVE_PACKETS:
                    if (wmEvent == BN_CLICKED) {
                        window->SaveAdapterPackets(window->selectedAdapterIp);
                        return 0;
                    }
                    break;
                case IDC_OPEN_RULES:
                    if (wmEvent == BN_CLICKED) {
                        window->OpenRulesDialog();
                        return 0;
                    }
                    break;
                case IDC_OPEN_SETTINGS:
                    if (wmEvent == BN_CLICKED) {
                        window->OpenSettingsDialog();
                        return 0;
                    }
                    break;
                case IDC_CLEAR_SAVED_PACKETS:
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
        
    }
    catch (const std::exception& e) {
        OutputDebugStringA("Exception in WndProc: ");
        OutputDebugStringA(e.what());
        OutputDebugStringA("\n");
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

INT_PTR CALLBACK MainWindow::PacketPropertiesDialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        GroupedPacketInfo* packet = reinterpret_cast<GroupedPacketInfo*>(lParam);
        if (!packet) return FALSE;

        SetDlgItemText(hwnd, IDC_SOURCE_DOMAIN, L"Запрос...");
        SetDlgItemText(hwnd, IDC_DEST_DOMAIN, L"Запрос...");

        // Время первого появления пакета
        if (!packet->time.empty()) {
            std::wstring timeStr = L"Первое появление: " + StringToWString(packet->time);
            SetDlgItemText(hwnd, IDC_TIME, timeStr.c_str());
        }
        else {
            SetDlgItemText(hwnd, IDC_TIME, L"Время не определено");
        }

        // Сетевая информация
        SetDlgItemText(hwnd, IDC_SOURCE,
            (StringToWString(packet->sourceIp) + L":" +
                std::to_wstring(packet->sourcePort)).c_str());

        SetDlgItemText(hwnd, IDC_DEST,
            (StringToWString(packet->destIp) + L":" +
                std::to_wstring(packet->destPort)).c_str());

        SetDlgItemText(hwnd, IDC_PROTOCOL,
            StringToWString(packet->protocol).c_str());

        // Информация о процессе
        SetDlgItemText(hwnd, IDC_PID,
            std::to_wstring(packet->processId).c_str());

        SetDlgItemText(hwnd, IDC_PROCESS_NAME,
            StringToWString(packet->processName).c_str());

        std::string sourceIp = packet->sourceIp;
        std::string destIp = packet->destIp;

        std::thread([hwnd, sourceIp, destIp]() {
            std::string srcDom = GetDomainByIp(sourceIp);
            std::string dstDom = GetDomainByIp(destIp);
            // Обновление GUI из фонового потока: используем SendMessage/PostMessage через кастомное сообщение или простой вызов SetDlgItemText в main thread
            std::wstring srcW = srcDom.empty() ? L"(нет данных)" : MainWindow::StringToWString(srcDom);
            std::wstring dstW = dstDom.empty() ? L"(нет данных)" : MainWindow::StringToWString(dstDom);
            // Лучше через PostMessage + кастомное сообщение, но для простоты (если поток GUI не сильно используется):
            SendMessage(hwnd, WM_USER + 100, (WPARAM)new std::wstring(srcW), 1);
            SendMessage(hwnd, WM_USER + 100, (WPARAM)new std::wstring(dstW), 2);
            }).detach();

        // Путь процесса - если путь пустой, пробуем получить его снова
        std::string processPath = packet->processPath;
        if (processPath.empty()) {
            processPath = GetProcessPath(packet->processId);
        }

        SetDlgItemText(hwnd, IDC_PROCESS_PATH,
            processPath.empty() ? L"(путь недоступен)" : StringToWString(processPath).c_str());

        // Размер и количество пакетов
        std::wstring sizeStr = FormatFileSize(packet->totalSize) +
            L" (всего пакетов: " +
            std::to_wstring(packet->packetCount) + L")";
        SetDlgItemText(hwnd, IDC_SIZE, sizeStr.c_str());

        // Сохраняем указатель на пакет
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(packet));
        return TRUE;

        return TRUE;
    }
    case WM_USER + 100: {
        std::wstring* dom = reinterpret_cast<std::wstring*>(wParam);
        if (lParam == 1) // source
            SetDlgItemText(hwnd, IDC_SOURCE_DOMAIN, dom->c_str());
        else if (lParam == 2) // dest
            SetDlgItemText(hwnd, IDC_DEST_DOMAIN, dom->c_str());
        delete dom;
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            EndDialog(hwnd, LOWORD(wParam));
            return TRUE;

        case IDC_BLOCK_IP: {
            auto packet = reinterpret_cast<GroupedPacketInfo*>(
                GetWindowLongPtr(hwnd, GWLP_USERDATA));
            if (packet) {
                std::wstring msg = L"Заблокировать IP " +
                    StringToWString(packet->sourceIp) + L"?";
                if (MessageBox(hwnd, msg.c_str(), L"Подтверждение",
                    MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    //AddBlockingRule(packet->sourceIp);
                }
            }
            return TRUE;
        }
        }
        break;
    }
    return FALSE;
}

void MainWindow::OpenSettingsDialog() {
    DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_SETTINGS_DIALOG), hwnd, SettingsDialogProc, (LPARAM)this);
}

// Вспомогательная функция для получения имени фильтра
std::string GetFilterName(ProtocolFilter filter) {
    switch (filter) {
    case ProtocolFilter::All: return "All Protocols";
    case ProtocolFilter::TCP_UDP: return "TCP and UDP";
    case ProtocolFilter::TCP: return "TCP Only";
    case ProtocolFilter::UDP: return "UDP Only";
    default: return "Unknown";
    }
}

INT_PTR CALLBACK MainWindow::SettingsDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    MainWindow* window;
    if (uMsg == WM_INITDIALOG) {
        window = reinterpret_cast<MainWindow*>(lParam);
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)window);

        switch (window->settings.protocolFilter) {
        case ProtocolFilter::All:
            CheckRadioButton(hwndDlg, IDC_RADIO_ALL, IDC_RADIO_UDP, IDC_RADIO_ALL);
            break;
        case ProtocolFilter::TCP_UDP:
            CheckRadioButton(hwndDlg, IDC_RADIO_ALL, IDC_RADIO_UDP, IDC_RADIO_TCP_UDP);
            break;
        case ProtocolFilter::TCP:
            CheckRadioButton(hwndDlg, IDC_RADIO_ALL, IDC_RADIO_UDP, IDC_RADIO_TCP);
            break;
        case ProtocolFilter::UDP:
            CheckRadioButton(hwndDlg, IDC_RADIO_ALL, IDC_RADIO_UDP, IDC_RADIO_UDP);
            break;
        }
        // Обновить статус
        SetDlgItemText(hwndDlg, IDC_BLOCKER_STATUS,
            IsBlockerRunning() ? L"Статус: работает" : L"Статус: остановлен");
        return TRUE;
    }
    if (uMsg == WM_COMMAND) {
        if (LOWORD(wParam) == IDOK) {
            window = reinterpret_cast<MainWindow*>(GetWindowLongPtr(hwndDlg, GWLP_USERDATA));

            ProtocolFilter oldFilter = window->settings.protocolFilter;
            // Инициализируем значением по умолчанию
            ProtocolFilter newFilter = oldFilter; // значение по умолчанию - текущий фильтр

            if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_ALL))
                newFilter = ProtocolFilter::All;
            else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_TCP_UDP))
                newFilter = ProtocolFilter::TCP_UDP;
            else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_TCP))
                newFilter = ProtocolFilter::TCP;
            else if (IsDlgButtonChecked(hwndDlg, IDC_RADIO_UDP))
                newFilter = ProtocolFilter::UDP;

            // Логируем изменение фильтра только если он действительно изменился
            if (oldFilter != newFilter) {
                std::stringstream details;
                details << "Protocol filter changed\n"
                    << "Previous filter: " << GetFilterName(oldFilter) << "\n"
                    << "New filter: " << GetFilterName(newFilter);

                FirewallLogger::Instance().LogServiceEvent(
                    FirewallEventType::FILTER_CHANGED,
                    details.str()
                );
            }

            window->settings.protocolFilter = newFilter;
            EndDialog(hwndDlg, IDOK);
            window->UpdateGroupedPackets();
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_STOP_BLOCKER) {
            FirewallLogger::Instance().LogServiceEvent(
                FirewallEventType::FIREWALL_SERVICE_STOPPED,
                "Blocker process stopped by user"
            );
            StopBlockerProcess();
            Sleep(3000);
            SetDlgItemText(hwndDlg, IDC_BLOCKER_STATUS, L"Статус: остановлен");
            MessageBox(hwndDlg, L"Блокировщик остановлен", L"Информация", MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            // Добавим лог при закрытии окна настроек
            FirewallLogger::Instance().LogServiceEvent(
                FirewallEventType::SERVICE_EVENT,
                "Settings dialog closed without changes"
            );
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
        }
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