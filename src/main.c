/* =====================================================================
 * USB_safely — U盘锁（电脑防护程序）v0.1.0 初版
 * 设计来源：USB_safely 设计方案 v1 草案 & v2.0（JAC / Geek-Hub）
 * ---------------------------------------------------------------------
 * 功能（对应设计方案）：
 *   1. 全屏置顶无边框锁定界面，显示在所有程序上层
 *   2. 程序自带键盘（A-Z、0-9、* - # 共 39 键 + 退格），屏蔽系统快捷键
 *   3. 密码存储于 USB 根目录 /password/pw.sf（SHA256 哈希，不存明文）
 *   4. 首次使用自动进入"设置密码"流程
 *   5. 连续输错 5 次 → 锁定 60 秒（对应 v2.0 超级模式"试错 5 次"）
 *   6. 取消按钮 → 安全弹出 USB 设备并退出（对应手稿"退出：弹出USB设备"）
 *   7. 设置界面（USBsafely.exe setup 启动）：修改密码 / 关于程序 /
 *      版本号连点 5 次开启超级模式（对应手稿彩蛋）
 * ---------------------------------------------------------------------
 * 编译（Linux 交叉编译）：
 *   x86_64-w64-mingw32-gcc main.c -o USBsafely.exe -municode -mwindows \
 *       -luser32 -lgdi32 -lbcrypt -lcfgmgr32 -lshell32 -ladvapi32
 * ===================================================================== */
#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <cfgmgr32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* {53f56307-b6bf-11d0-94d2-00a0c91efb8b} 磁盘设备接口 */
#include <initguid.h>
DEFINE_GUID(GUID_DEVINTERFACE_DISK,
    0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xd2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);

#define APP_NAME    L"USB_safely"
#define APP_VER     L"V0.1.0"
#define TEAM_NAME   L"JAC · Geek-Hub"
#define MAX_PWD     32
#define MAX_WRONG   5
#define LOCKOUT_SEC 60

/* ---------------- 全局状态 ---------------- */
static HINSTANCE g_hInst;
static WCHAR     g_root[MAX_PATH];        /* exe 所在盘，如 L"E:" */
static WCHAR     g_pwFile[MAX_PATH];      /* ...\password\pw.sf */
static int       g_wrong = 0;             /* 已输错次数 */
static time_t    g_lockUntil = 0;         /* 锁定截止时间 */
static HHOOK     g_kbHook = NULL;

static HWND g_hLockWnd = NULL;
static HWND g_hSetupWnd = NULL;
static HWND g_hDisplay = NULL;            /* 密码显示区（自绘） */

static HWND g_keys[64];                   /* 自带键盘按钮 */
static int  g_keyCount = 0;
static int  g_keyChar[64];                /* 对应字符（或 -1=退格） */

static WCHAR g_input[MAX_PWD + 1];        /* 当前输入 */
static int   g_inputLen = 0;

/* 设置窗口控件 */
static HWND g_hOld, g_hNew, g_hNew2, g_hVerLabel, g_hAboutOld;
static int  g_verClicks = 0;

/* ---------------- SHA256（BCrypt，系统自带） ---------------- */
static BOOL Sha256Hex(const WCHAR *text, WCHAR outHex[65])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE hash[32];
    DWORD cb = 0, cbOut = 32;
    BOOL ok = FALSE;
    int need; char *utf8;

    if (FAILED(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return FALSE;
    if (FAILED(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cb, sizeof(cb), &cb, 0)) || cb != 32)
        goto done;
    if (FAILED(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
        goto done;
    need = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (need <= 0) goto done;
    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, need);
    if (!utf8) goto done;
    WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, need, NULL, NULL);
    BCryptHashData(hHash, (PUCHAR)utf8, (ULONG)need - 1, 0);   /* 不含结尾 \0 */
    HeapFree(GetProcessHeap(), 0, utf8);
    if (FAILED(BCryptFinishHash(hHash, hash, 32, 0))) goto done;
    for (int i = 0; i < 32; i++) wsprintfW(outHex + i * 2, L"%02x", hash[i]);
    outHex[64] = 0;
    ok = TRUE;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static BOOL LoadPasswordHex(WCHAR hex[65])
{
    FILE *f = _wfopen(g_pwFile, L"r");
    if (!f) return FALSE;
    memset(hex, 0, 65 * sizeof(WCHAR));
    wchar_t line[128];
    BOOL ok = FALSE;
    if (fgetws(line, 128, f)) {
        wchar_t *p = line;
        while (*p == L' ' || *p == L'\t') p++;
        int n = 0;
        while (p[n] && p[n] != L'\r' && p[n] != L'\n' && n < 64) n++;
        if (n == 64) { memcpy(hex, p, 64 * sizeof(WCHAR)); hex[64] = 0; ok = TRUE; }
    }
    fclose(f);
    return ok;
}

static BOOL SavePasswordHex(const WCHAR hex[65])
{
    CreateDirectoryW(g_pwFile, NULL) ? 0 : 0;   /* 失败无妨（目录已存在时） */
    /* 确保上级目录存在 */
    WCHAR dir[MAX_PATH]; wcscpy(dir, g_pwFile);
    WCHAR *slash = wcsrchr(dir, L'\\');
    if (slash) { *slash = 0; CreateDirectoryW(dir, NULL); }
    FILE *f = _wfopen(g_pwFile, L"w");
    if (!f) return FALSE;
    fwprintf(f, L"%s\n", hex);
    fclose(f);
    return TRUE;
}

static BOOL CheckPassword(const WCHAR *input)
{
    WCHAR hex[65], want[65];
    if (!Sha256Hex(input, hex)) return FALSE;
    if (!LoadPasswordHex(want)) return FALSE;
    return _wcsicmp(hex, want) == 0;
}

/* ---------------- 键盘钩子：屏蔽快捷键 ---------------- */
static LRESULT CALLBACK LowLevelProc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)lp;
        BOOL alt  = GetAsyncKeyState(VK_MENU)   & 0x8000;
        BOOL ctrl = GetAsyncKeyState(VK_CONTROL)& 0x8000;
        if (k->vkCode == VK_LWIN || k->vkCode == VK_RWIN) return 1;
        if (alt && (k->vkCode == VK_TAB || k->vkCode == VK_F4 || k->vkCode == VK_ESCAPE)) return 1;
        if (ctrl && k->vkCode == VK_ESCAPE) return 1;
        if (ctrl && alt && (k->vkCode == VK_DELETE || k->vkCode == VK_RETURN)) return 1;
    }
    return CallNextHookEx(g_kbHook, code, wp, lp);
}

static void HookOn(void)  { if (!g_kbHook) g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelProc, g_hInst, 0); }
static void HookOff(void) { if (g_kbHook) { UnhookWindowsHookEx(g_kbHook); g_kbHook = NULL; } }

/* ---------------- 安全弹出 USB 设备 ---------------- */
static BOOL EjectUsb(HWND owner)
{
    WCHAR volPath[8], volName[MAX_PATH + 1] = L"";
    wsprintfW(volPath, L"%s\\", g_root);
    if (!GetVolumeNameForVolumeMountPointW(volPath, volName, MAX_PATH))
        return FALSE;

    /* 1. 拿到该盘符对应物理磁盘号 */
    HANDLE hVol = CreateFileW(volPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return FALSE;
    STORAGE_DEVICE_NUMBER sdn; DWORD ret = 0;
    if (!DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                         &sdn, sizeof(sdn), &ret, NULL)) { CloseHandle(hVol); return FALSE; }
    CloseHandle(hVol);

    /* 2. 枚举磁盘接口，匹配同一块物理盘，取设备实例 */
    ULONG size = 0;
    if (CM_Get_Device_Interface_List_SizeW(&size, (LPGUID)&GUID_DEVINTERFACE_DISK,
            NULL, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
        return FALSE;
    WCHAR *list = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    if (!list) return FALSE;
    if (CM_Get_Device_Interface_ListW((LPGUID)&GUID_DEVINTERFACE_DISK, NULL, list,
            size, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, list); return FALSE;
    }

    DEVINST devFound = 0;
    for (WCHAR *p = list; *p; p += wcslen(p) + 1) {
        HANDLE h = CreateFileW(p, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        STORAGE_DEVICE_NUMBER n2;
        if (DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                            &n2, sizeof(n2), &ret, NULL) && n2.DeviceNumber == sdn.DeviceNumber) {
            /* 接口路径 → 设备实例 ID：
               \\?\usbstor#disk&ven_x#sn#{guid} → USBSTOR\DISK&VEN_X\SN */
            WCHAR id[512] = L"";
            const WCHAR *q = p + 4;                     /* 跳过 \\?\ */
            const WCHAR *end = wcsrchr(q, L'#');        /* 最后一个 '#' 前 */
            if (!end) end = q + wcslen(q);
            size_t n = 0;
            for (; q < end && n < 510; q++, n++) {
                if (q[0] == L'#' && q[1] == L'{') break;   /* 遇到 #{guid} 截断 */
                id[n] = (q[0] == L'#') ? L'\\' : q[0];
            }
            id[n] = 0;
            DEVINST dn = 0;
            if (CM_Locate_DevNodeW(&dn, (DEVINSTID_W)id, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
                devFound = dn;
        }
        CloseHandle(h);
        if (devFound) break;
    }
    HeapFree(GetProcessHeap(), 0, list);
    if (!devFound) return FALSE;

    /* 3. 逐级向上找 USB 设备节点并弹出 */
    DEVINST cur = devFound;
    for (int i = 0; i < 2; i++) {
        DEVINST parent = 0;
        if (CM_Get_Parent(&parent, cur, 0) != CR_SUCCESS) break;
        cur = parent;
        if (CM_Request_Device_Eject_ExW(cur, NULL, NULL, 0, 0, NULL) == CR_SUCCESS)
            return TRUE;
    }
    return CM_Request_Device_Eject_ExW(devFound, NULL, NULL, 0, 0, NULL) == CR_SUCCESS;
}

/* ---------------- 锁定界面 ---------------- */
#define IDC_CONFIRM   1001
#define IDC_CANCEL    1002
#define IDC_BACKSPACE 1003
#define IDC_KEYBASE   2000

static const wchar_t *ROWS[4] = {
    L"1234567890",
    L"QWERTYUIOP",
    L"ASDFGHJKL*",
    L"ZXCVBNM-#"
};

static void InputAppend(wchar_t c)
{
    if (g_inputLen < MAX_PWD) { g_input[g_inputLen++] = c; g_input[g_inputLen] = 0; InvalidateRect(g_hDisplay, NULL, TRUE); }
}
static void InputBack(void)
{
    if (g_inputLen > 0) { g_inputLen--; g_input[g_inputLen] = 0; InvalidateRect(g_hDisplay, NULL, TRUE); }
}
static void InputClear(void)
{
    g_inputLen = 0; g_input[0] = 0; InvalidateRect(g_hDisplay, NULL, TRUE);
}

static void SetButtonsEnabled(HWND wnd, BOOL en)
{
    for (int i = 0; i < g_keyCount; i++) if (g_keys[i]) EnableWindow(g_keys[i], en);
    HWND c = GetDlgItem(wnd, IDC_CONFIRM), x = GetDlgItem(wnd, IDC_CANCEL);
    if (c) EnableWindow(c, en);
    if (x) EnableWindow(x, en);
}

static void OnWrongPassword(HWND wnd)
{
    time_t now = time(NULL);
    if (now < g_lockUntil) return;
    g_wrong++;
    InputClear();
    if (g_wrong >= MAX_WRONG) {
        g_wrong = 0;
        g_lockUntil = now + LOCKOUT_SEC;
        SetTimer(wnd, 1, 1000, NULL);
        SetButtonsEnabled(wnd, FALSE);
        SetWindowTextW(wnd, APP_NAME L" — 已临时锁定");
    }
    InvalidateRect(wnd, NULL, TRUE);
}

static void UnlockSuccess(HWND wnd)
{
    HookOff();
    KillTimer(wnd, 1);
    MessageBoxW(wnd, L"✔ 密码正确，电脑已解锁！\n\n本程序即将退出。", APP_NAME, MB_OK | MB_ICONINFORMATION);
    DestroyWindow(wnd);
}

static void BuildKeyboard(HWND parent)
{
    g_keyCount = 0;
    for (int r = 0; r < 4; r++) {
        int n = (int)wcslen(ROWS[r]);
        for (int c = 0; c < n; c++) {
            wchar_t label[2] = { ROWS[r][c], 0 };
            HWND b = CreateWindowW(L"BUTTON", label,
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    0, 0, 10, 10, parent,
                    (HMENU)(INT_PTR)(IDC_KEYBASE + g_keyCount), g_hInst, NULL);
            SendMessageW(b, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
            g_keys[g_keyCount] = b;
            g_keyChar[g_keyCount] = ROWS[r][c];
            g_keyCount++;
        }
        HWND bs = CreateWindowW(L"BUTTON", L"⌫",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 10, 10, parent, (HMENU)(INT_PTR)IDC_BACKSPACE, g_hInst, NULL);
        SendMessageW(bs, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
        g_keys[g_keyCount] = bs;
        g_keyChar[g_keyCount] = -1;
        g_keyCount++;
    }
}

static void LayoutLock(HWND wnd)
{
    RECT rc; GetClientRect(wnd, &rc);
    int W = rc.right, H = rc.bottom;
    int kbW = W < 900 ? W - 40 : 860;
    int kbH = H / 2;
    int x0 = (W - kbW) / 2;
    int y0 = H - kbH - 30;
    int cols = 10, rows = 4;
    int bw = kbW / cols - 8, bh = kbH / rows - 8;
    int i = 0;
    for (int r = 0; r < rows; r++)
        for (int c = 0; c <= cols; c++) {
            if (i >= g_keyCount) break;
            int isExtra = (c == cols);      /* 每行末尾的退格 */
            SetWindowPos(g_keys[i], NULL,
                x0 + c * (bw + 8), y0 + r * (bh + 8),
                isExtra ? bw : bw, bh, SWP_NOZORDER);
            i++;
        }
    if (g_hDisplay) SetWindowPos(g_hDisplay, NULL, x0, y0 - 130, kbW, 60, SWP_NOZORDER);
    HWND hC = GetDlgItem(wnd, IDC_CONFIRM), hX = GetDlgItem(wnd, IDC_CANCEL);
    if (hC) SetWindowPos(hC, NULL, W / 2 - 170, y0 - 55, 160, 40, SWP_NOZORDER);
    if (hX) SetWindowPos(hX, NULL, W / 2 + 10,  y0 - 55, 160, 40, SWP_NOZORDER);
}

static void PaintLock(HWND wnd, HDC dc)
{
    RECT rc; GetClientRect(wnd, &rc);
    SetBkMode(dc, TRANSPARENT);
    HBRUSH bg = CreateSolidBrush(RGB(12, 18, 32));
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    int W = rc.right;
    time_t now = time(NULL);
    COLORREF main = RGB(230, 238, 248);
    if (now < g_lockUntil) {
        int left = (int)(g_lockUntil - now);
        wchar_t buf[96];
        wsprintfW(buf, L"⛔ 输错次数过多，请等待 %d 秒后再试", left);
        SetTextColor(dc, RGB(248, 113, 113));
        HFONT f = CreateFontW(40, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        HFONT of = (HFONT)SelectObject(dc, f);
        RECT tr = { 0, 60, W, 130 };
        DrawTextW(dc, buf, -1, &tr, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, of); DeleteObject(f);
        return;
    }

    /* 主标题 / 副标题（v2.0 锁定页面） */
    HFONT f1 = CreateFontW(52, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f2 = CreateFontW(30, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f3 = CreateFontW(36, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    SetTextColor(dc, main);
    RECT t1 = { 0, 40, W, 120 };
    DrawTextW(dc, L"此 USB 设备已被锁定", -1, &t1, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SetTextColor(dc, RGB(140, 160, 190));
    RECT t2 = { 0, 125, W, 170 };
    DrawTextW(dc, L"请输入解锁密钥", -1, &t2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    /* 剩余次数提示 */
    if (g_wrong > 0) {
        wchar_t buf[80];
        wsprintfW(buf, L"密码错误 %d 次，再错 %d 次将锁定 %d 秒", g_wrong, MAX_WRONG - g_wrong, LOCKOUT_SEC);
        SetTextColor(dc, RGB(250, 190, 120));
        RECT t3 = { 0, 175, W, 210 };
        DrawTextW(dc, buf, -1, &t3, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    /* 密码显示区 */
    if (g_hDisplay) {
        wchar_t mask[MAX_PWD * 2 + 1];
        if (g_inputLen == 0) wcscpy(mask, L"");
        else {
            int i;
            for (i = 0; i < g_inputLen && i < MAX_PWD; i++) mask[i] = L'●';
            mask[i] = 0;
        }
        RECT dr; GetClientRect(g_hDisplay, &dr);
        POINT pt = { 0, 0 }; MapWindowPoints(g_hDisplay, wnd, &pt, 1);
        OffsetRect(&dr, pt.x, pt.y);
        FillRect(dc, &dr, CreateSolidBrush(RGB(24, 34, 54)));
        FrameRect(dc, &dr, CreateSolidBrush(RGB(76, 194, 255)));
        SetTextColor(dc, RGB(76, 194, 255));
        SelectObject(dc, f3);
        RECT inner = dr; InflateRect(&inner, -8, -8);
        if (g_inputLen == 0) {
            SetTextColor(dc, RGB(90, 108, 136));
            DrawTextW(dc, L"（使用屏幕键盘输入）", -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        } else
            DrawTextW(dc, mask, -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    SelectObject(dc, f1); DeleteObject(f1);
    SelectObject(dc, f2); DeleteObject(f2);
    SelectObject(dc, f3); DeleteObject(f3);
}

static LRESULT CALLBACK LockProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        g_hDisplay = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                0, 0, 10, 10, wnd, NULL, g_hInst, NULL);
        CreateWindowW(L"BUTTON", L"✔ 确认解锁", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 160, 40, wnd, (HMENU)(INT_PTR)IDC_CONFIRM, g_hInst, NULL);
        CreateWindowW(L"BUTTON", L"⏏ 取消并弹出U盘", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 160, 40, wnd, (HMENU)(INT_PTR)IDC_CANCEL, g_hInst, NULL);
        BuildKeyboard(wnd);
        SetTimer(wnd, 2, 500, NULL);     /* 保置顶 */
        return 0;
    }
    case WM_TIMER:
        if (wp == 2) SetWindowPos(wnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        if (wp == 1) {
            time_t now = time(NULL);
            if (now >= g_lockUntil) {
                KillTimer(wnd, 1);
                SetButtonsEnabled(wnd, TRUE);
                SetWindowTextW(wnd, APP_NAME);
            } else
                SetWindowTextW(wnd, APP_NAME L" — 已临时锁定");
        }
        return 0;
    case WM_SIZE:
        LayoutLock(wnd);
        InvalidateRect(wnd, NULL, TRUE);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(wnd, &ps);
        PaintLock(wnd, dc);
        EndPaint(wnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_hDisplay) return (LRESULT)GetStockObject(NULL_BRUSH);
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wp);
        time_t now = time(NULL);
        if (now < g_lockUntil) return 0;
        if (id == IDC_BACKSPACE) InputBack();
        else if (id == IDC_CONFIRM) {
            if (g_inputLen == 0) return 0;
            WCHAR tmp[MAX_PWD + 1]; wcscpy(tmp, g_input);
            if (CheckPassword(tmp)) UnlockSuccess(wnd);
            else OnWrongPassword(wnd);
        }
        else if (id == IDC_CANCEL) {
            if (MessageBoxW(wnd, L"确定取消并弹出 USB 设备吗？\n（程序将关闭并安全弹出U盘）",
                    APP_NAME, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                HookOff();
                if (!EjectUsb(wnd))
                    MessageBoxW(wnd, L"弹出失败：可能有文件正在被占用，请手动弹出。",
                        APP_NAME, MB_OK | MB_ICONWARNING);
                ExitProcess(0);
            }
        }
        else if (id >= IDC_KEYBASE && id < IDC_KEYBASE + g_keyCount) {
            int ch = g_keyChar[id - IDC_KEYBASE];
            if (ch == -1) InputBack();
            else InputAppend((wchar_t)ch);
        }
        return 0;
    }
    case WM_DESTROY:
        KillTimer(wnd, 1); KillTimer(wnd, 2);
        if (g_hLockWnd == wnd) { g_hLockWnd = NULL; HookOff(); PostQuitMessage(0); }
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

/* ---------------- 设置窗口（setup 模式） ---------------- */
#define IDC_EDOLD    3001
#define IDC_EDNEW    3002
#define IDC_EDNEW2   3003
#define IDC_BTNCHG   3004
#define IDC_VERLBL   3005

static void ShowSuperMode(HWND wnd)
{
    MessageBoxW(wnd,
        L"🔓 超级模式已开启！（管理员模式）\n\n"
        L"说明：忘记密码时允许试错 5 次恢复（此功能将在 V2.0 实现），\n"
        L"当前初版已记录你的开启请求。",
        L"USB_safely 超级模式", MB_OK | MB_ICONINFORMATION);
}

static void DoChangePassword(HWND wnd)
{
    wchar_t old[MAX_PWD + 1], nw1[MAX_PWD + 1], nw2[MAX_PWD + 1];
    GetWindowTextW(g_hOld,  old,  MAX_PWD + 1);
    GetWindowTextW(g_hNew,  nw1,  MAX_PWD + 1);
    GetWindowTextW(g_hNew2, nw2,  MAX_PWD + 1);
    if (!old[0] || !nw1[0]) { MessageBoxW(wnd, L"密码不能为空", APP_NAME, MB_ICONWARNING); return; }
    if (wcscmp(nw1, nw2) != 0) { MessageBoxW(wnd, L"两次输入的新密码不一致", APP_NAME, MB_ICONWARNING); return; }
    if (wcslen(nw1) > MAX_PWD) { MessageBoxW(wnd, L"密码过长（最多32位）", APP_NAME, MB_ICONWARNING); return; }
    WCHAR ohex[65];
    if (LoadPasswordHex(ohex)) {
        WCHAR ihex[65];
        Sha256Hex(old, ihex);
        if (_wcsicmp(ihex, ohex) != 0) { MessageBoxW(wnd, L"旧密码错误！", APP_NAME, MB_ICONWARNING); return; }
    }
    WCHAR hex[65];
    Sha256Hex(nw1, hex);
    if (SavePasswordHex(hex)) {
        MessageBoxW(wnd, L"✔ 密码修改成功！", APP_NAME, MB_OK | MB_ICONINFORMATION);
        SetWindowTextW(g_hOld, L""); SetWindowTextW(g_hNew, L""); SetWindowTextW(g_hNew2, L"");
    } else
        MessageBoxW(wnd, L"写入密码文件失败", APP_NAME, MB_ICONERROR);
}

static LRESULT CALLBACK SetupProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT f  = CreateFontW(22, 0, 0, 0, FW_BOLD,   0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        HFONT fn = CreateFontW(17, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        CreateWindowW(L"STATIC", L"── 修改密码 ──", WS_CHILD|WS_VISIBLE, 30, 25, 340, 30, wnd, NULL, g_hInst, NULL);
        #define LB(txt,x,y,id) CreateWindowW(L"STATIC", txt, WS_CHILD|WS_VISIBLE, 30, y, 110, 24, wnd, NULL, g_hInst, NULL)
        #define ED(y,id) CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL, 145, y, 240, 28, wnd, (HMENU)(INT_PTR)id, g_hInst, NULL)
        LB(L"旧密码：", 0, 65,  0); g_hOld  = ED(63,  IDC_EDOLD);
        LB(L"新密码：", 0, 105, 0); g_hNew  = ED(103, IDC_EDNEW);
        LB(L"再输入：", 0, 145, 0); g_hNew2 = ED(143, IDC_EDNEW2);
        HWND chg = CreateWindowW(L"BUTTON", L"修改密码", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 145, 185, 160, 34, wnd, (HMENU)(INT_PTR)IDC_BTNCHG, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"（最多 32 位，字符限 A-Z 0-9 * - #）", WS_CHILD|WS_VISIBLE, 30, 225, 360, 22, wnd, NULL, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 关于程序 ──", WS_CHILD|WS_VISIBLE, 30, 275, 340, 30, wnd, NULL, g_hInst, NULL);
        g_hVerLabel = CreateWindowW(L"BUTTON", L"版本 " APP_VER L"（连点5下开启超级模式）",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|BS_LEFT, 30, 315, 355, 34, wnd, (HMENU)(INT_PTR)IDC_VERLBL, g_hInst, NULL);
        wchar_t about[256];
        wsprintfW(about, L"USB_safely — U盘锁\n制作团队：%s\nU盘锁防护程序，防止电脑被人查看", TEAM_NAME);
        g_hAboutOld = CreateWindowW(L"STATIC", about, WS_CHILD|WS_VISIBLE, 30, 365, 360, 90, wnd, NULL, g_hInst, NULL);
        /* 统一字体 */
        SendMessageW(g_hOld, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hNew, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hNew2, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(chg, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hVerLabel, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hAboutOld, WM_SETFONT, (WPARAM)fn, TRUE);
        DeleteObject(f); DeleteObject(fn);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BTNCHG) DoChangePassword(wnd);
        else if (id == IDC_VERLBL) {
            g_verClicks++;
            if (g_verClicks >= 5) { g_verClicks = 0; ShowSuperMode(wnd); }
        }
        return 0;
    }
    case WM_DESTROY:
        g_hSetupWnd = NULL;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

/* ---------------- 入口 ---------------- */
static ATOM RegOneClass(WNDPROC proc, const wchar_t *name)
{
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = proc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(12, 18, 32));
    wc.lpszClassName = name;
    return RegisterClassW(&wc);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE prev, LPWSTR cmd, int show)
{
    (void)prev; (void)show;
    g_hInst = hInst;

    /* exe 所在 U 盘（取盘符，如 L"E:"），密码文件固定在 U 盘根目录 password\pw.sf */
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t drive[4] = { exe[0], L':', 0 };
    wcscpy(g_root, drive);
    wsprintfW(g_pwFile, L"%s\\password", g_root);
    CreateDirectoryW(g_pwFile, NULL);
    wcscat(g_pwFile, L"\\pw.sf");

    

    BOOL setupMode = (cmd && (wcsstr(cmd, L"setup") || wcsstr(cmd, L"config")));

    if (setupMode) {
        RegOneClass(SetupProc, L"USBsafelySetup");
        g_hSetupWnd = CreateWindowW(L"USBsafelySetup", L"USB_safely 设置",
            (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME) | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 430, 520,
            NULL, NULL, hInst, NULL);
        MSG m;
        while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
        return 0;
    }

    /* 锁定模式：无密码文件 → 先引导设置 */
    WCHAR hex[65];
    if (!LoadPasswordHex(hex)) {
        MessageBoxW(NULL,
            L"检测到首次使用：U 盘中还没有密码文件。\n\n"
            L"请先设置锁屏密码（修改密码→保存即可），\n"
            L"设置完成后关闭本窗口，程序将自动进入锁定模式。",
            APP_NAME, MB_OK | MB_ICONINFORMATION);
        RegOneClass(SetupProc, L"USBsafelySetup");
        g_hSetupWnd = CreateWindowW(L"USBsafelySetup", L"USB_safely 首次设置",
            (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME) | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 430, 520,
            NULL, NULL, hInst, NULL);
        MSG m;
        while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
        if (!LoadPasswordHex(hex)) return 1;    /* 用户关闭了设置窗口 */
    }

    /* 进入锁定 */
    HookOn();
    RegOneClass(LockProc, L"USBsafelyLock");
    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);
    g_hLockWnd = CreateWindowExW(WS_EX_TOPMOST, L"USBsafelyLock", APP_NAME,
        WS_POPUP | WS_VISIBLE, 0, 0, sx, sy, NULL, NULL, hInst, NULL);
    SetFocus(g_hLockWnd);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
