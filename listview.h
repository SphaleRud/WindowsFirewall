#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

class ListView {
public:
    struct Column {
        std::wstring text;
        int width;
    };

    ListView() : hwnd(nullptr), columnCount(0) {}
    operator bool() const {
        return hwnd != nullptr;
    }

    bool Initialize(HWND parent, int x, int y, int width, int height, HMENU id, HINSTANCE hInstance) {
        hwnd = CreateWindowEx(
            0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER,
            x, y, width, height,
            parent, id,
            hInstance, NULL
        );

        if (!hwnd) return false;

        // Устанавливаем расширенный стиль
        ListView_SetExtendedListViewStyle(hwnd, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        return true;
    }

    bool AddColumn(const std::wstring& text, int width, int index) {
        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.pszText = const_cast<LPWSTR>(text.c_str());
        lvc.cx = width;
        lvc.iSubItem = index;

        return ListView_InsertColumn(hwnd, index, &lvc) != -1;
    }

    bool AddItem(const std::vector<std::wstring>& items) {
        if (items.empty()) return false;

        // Ограничение на количество элементов (опционально)
        const size_t MAX_ITEMS = 1000;
        int currentCount = ListView_GetItemCount(hwnd);
        if (currentCount >= MAX_ITEMS) {
            // Удаляем последний элемент
            ListView_DeleteItem(hwnd, currentCount - 1);
        }

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = 0; // Вставляем в начало списка
        lvi.pszText = const_cast<LPWSTR>(items[0].c_str());

        int index = ListView_InsertItem(hwnd, &lvi);
        if (index == -1) return false;

        for (size_t i = 1; i < items.size(); ++i) {
            ListView_SetItemText(hwnd, index, static_cast<int>(i),
                const_cast<LPWSTR>(items[i].c_str()));
        }

        // Прокручиваем к верху списка
        ListView_EnsureVisible(hwnd, 0, FALSE);

        return true;
    }

    // Добавляем перегрузку для вставки в конец списка (если понадобится)
    bool AddItemToBottom(const std::vector<std::wstring>& items) {
        if (items.empty()) return false;

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hwnd); // Вставляем в конец списка
        lvi.pszText = const_cast<LPWSTR>(items[0].c_str());

        int index = ListView_InsertItem(hwnd, &lvi);
        if (index == -1) return false;

        for (size_t i = 1; i < items.size(); ++i) {
            ListView_SetItemText(hwnd, index, static_cast<int>(i),
                const_cast<LPWSTR>(items[i].c_str()));
        }

        return true;
    }

    int GetSelectedIndex() const {
        return ListView_GetNextItem(hwnd, -1, LVNI_SELECTED);
    }

    bool DeleteItem(int index) {
        return ListView_DeleteItem(hwnd, index) != 0;
    }

    // Получить количество элементов
    int GetItemCount() const {
        return ListView_GetItemCount(hwnd);
    }

    void Clear() {
        ListView_DeleteAllItems(hwnd);
    }

    HWND GetHandle() const {
        return hwnd;
    }

private:
    HWND hwnd;
    int columnCount;
};