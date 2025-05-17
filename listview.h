#pragma once
#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <vector>

class ListView {
public:
    ListView() : hwnd(nullptr) {}
    ~ListView() = default;

    ListView& operator=(HWND h) {
        hwnd = h;
        return *this;
    }

    void SetHandle(HWND h) { hwnd = h; }

    HWND GetHandle() const { return hwnd; }

    bool Create(HWND parent, HINSTANCE hInst, DWORD style, int x, int y, int width, int height, HMENU id) {
        hwnd = CreateWindowEx(
            0, WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | style,
            x, y, width, height,
            parent,
            id,
            hInst,
            NULL);

        return hwnd != nullptr;
    }

    void AddColumn(int index, const std::wstring& text, int width) {
        if (!hwnd) return;
        LVCOLUMN lvc = { 0 };
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.cx = width;
        lvc.pszText = const_cast<LPWSTR>(text.c_str());
        lvc.iSubItem = index;
        ListView_InsertColumn(hwnd, index, &lvc);
    }

    int AddItem(const std::vector<std::wstring>& items) {
        if (!hwnd || items.empty()) return -1;

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hwnd);
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(items[0].c_str());
        int index = ListView_InsertItem(hwnd, &lvi);

        for (size_t i = 1; i < items.size(); ++i) {
            ListView_SetItemText(hwnd, index, static_cast<int>(i),
                const_cast<LPWSTR>(items[i].c_str()));
        }

        return index;
    }

    void Clear() {
        if (hwnd) ListView_DeleteAllItems(hwnd);
    }

    operator HWND() const { return hwnd; }
    explicit operator bool() const { return hwnd != nullptr; }

private:
    HWND hwnd;
};