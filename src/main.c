/* =====================================================================
 * USB_safely — U盘锁 v2.0.0 主程序
 * 设计来源：USB_safely 设计方案（JAC）· 见仓库 DESIGN.md
 * ---------------------------------------------------------------------
 * v2.0 功能（对照 DESIGN.md）：
 *   1. 解锁模式分级：0无需解锁 / 1普通(数字) / 2加密(字母) /
 *      3进阶(9位混合) / 4密钥模式(≤500位任意字符)
 *   2. 递进惩罚：每累计错 5 次 → 锁定 (次数÷5)×10 分钟递增；
 *      超过 60 次（可选，默认关）→ 格式化清除
 *   3. 后台待命：解锁后缩到托盘，可一键重新锁定；U盘拔出自动退出；
 *      退出程序需密码确认（卸载保护第一层）
 *   4. 超级模式：设置页版本号连点 5 次 → 验证恢复密码 →
 *      重置锁屏密码 / 忘记密码定时重置 / 格式化开关
 *   5. 密码 SHA256 存储；路径基于安装目录（U盘根目录或硬盘安装目录）
 * ---------------------------------------------------------------------
 * 编译（Linux 交叉编译）：
 *   x86_64-w64-mingw32-gcc main.c -o USBsafely.exe -municode -mwindows -O2 \
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

#include <initguid.h>
/* {53f56307-b6bf-11d0-94d2-00a0c91efb8b} 磁盘设备接口 */
DEFINE_GUID(GUID_DEVINTERFACE_DISK,
    0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xd2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);

#define APP_NAME     L"USB_safely"
#define APP_VER      L"V2.0.0"
#define TEAM_NAME    L"JAC · Geek-Hub"
#define MAX_PWD      500      /* 密钥模式上限（DESIGN.md 第三节） */

/* ---------------- 全局状态 ---------------- */
static HINSTANCE g_hInst;
static WCHAR     g_dir[MAX_PATH];         /* 安装目录（exe 所在目录） */
static WCHAR     g_pwFile[MAX_PATH];      /* <dir>\password\pw.sf */
static WCHAR     g_stateFile[MAX_PATH];   /* <dir>\password\state.sf */
static WCHAR     g_recFile[MAX_PATH];     /* <dir>\password\recovery.sf */

typedef struct {
    int      mode;            /* 0/1/2/3/4 */
    int      fails;           /* 累计错误次数 */
    long long lockUntil;      /* 当前锁定截止时间戳 */
    long long forgetDeadline; /* 忘记密码重置期限，0=关闭 */
    int      formatOn;        /* 超60次格式化开关，默认0 */
    int      uninstProt;      /* 退出需密码，默认1 */
} STATE;
static STATE g_state = { 4, 0, 0, 0, 0, 1 };

static HHOOK  g_kbHook = NULL;
static HWND   g_hLockWnd = NULL, g_hTrayWnd = NULL;
static HWND   g_hDisplay = NULL;
static HWND   g_keys[64];
static int    g_keyCount = 0, g_keyChar[64];
static WCHAR  g_input[MAX_PWD + 1];
static int    g_inputLen = 0;

/* 设置窗口控件句柄 */
static HWND g_hOld, g_hNew, g_hNew2, g_hVerLabel, g_hAbout, g_hModeCombo;
/* 超级模式窗口控件 */
static HWND g_hRecEdit, g_hSupPanel, g_hSupNew1, g_hSupNew2, g_hSupForget, g_hSupFmt;

/* ---------------- 工具函数 ---------------- */
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
    BCryptHashData(hHash, (PUCHAR)utf8, (ULONG)need - 1, 0);
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

static BOOL ReadHexFile(const WCHAR *file, WCHAR hex[65])
{
    FILE *f = _wfopen(file, L"r");
    if (!f) return FALSE;
    memset(hex, 0, 65 * sizeof(WCHAR));
    wchar_t line[256];
    BOOL ok = FALSE;
    if (fgetws(line, 256, f)) {
        wchar_t *p = line;
        while (*p == L' ' || *p == L'\t') p++;
        int n = 0;
        while (p[n] && p[n] != L'\r' && p[n] != L'\n' && n < 64) n++;
        if (n == 64) { memcpy(hex, p, 64 * sizeof(WCHAR)); hex[64] = 0; ok = TRUE; }
    }
    fclose(f);
    return ok;
}

static BOOL CheckPassword(const WCHAR *input)
{
    WCHAR hex[65], want[65];
    if (!Sha256Hex(input, hex)) return FALSE;
    if (!ReadHexFile(g_pwFile, want)) return FALSE;
    return _wcsicmp(hex, want) == 0;
}

static BOOL SavePasswordHash(const WCHAR hex[65])
{
    FILE *f = _wfopen(g_pwFile, L"w");
    if (!f) return FALSE;
    fwprintf(f, L"%s\n", hex);
    fclose(f);
    return TRUE;
}

static BOOL CheckRecovery(const WCHAR *input)
{
    WCHAR hex[65], want[65];
    if (!Sha256Hex(input, hex)) return FALSE;
    if (!ReadHexFile(g_recFile, want)) return FALSE;
    return _wcsicmp(hex, want) == 0;
}

/* ---------------- 状态文件（明文 key=value，非机密） ---------------- */
static void LoadState(void)
{
    FILE *f = _wfopen(g_stateFile, L"r");
    if (!f) return;
    wchar_t line[128];
    while (fgetws(line, 128, f)) {
        wchar_t *eq = wcschr(line, L'=');
        if (!eq) continue;
        *eq = 0; long long v = wcstoll(eq + 1, NULL, 10);
        if      (!wcscmp(line, L"mode"))      g_state.mode = (int)v;
        else if (!wcscmp(line, L"fails"))     g_state.fails = (int)v;
        else if (!wcscmp(line, L"lockUntil")) g_state.lockUntil = v;
        else if (!wcscmp(line, L"forget"))    g_state.forgetDeadline = v;
        else if (!wcscmp(line, L"formatOn"))  g_state.formatOn = (int)v;
        else if (!wcscmp(line, L"uninstProt")) g_state.uninstProt = (int)v;
    }
    fclose(f);
    if (g_state.mode < 0 || g_state.mode > 4) g_state.mode = 4;
}

static void SaveState(void)
{
    FILE *f = _wfopen(g_stateFile, L"w");
    if (!f) return;
    fwprintf(f, L"mode=%d\nfails=%d\nlockUntil=%lld\nforget=%lld\nformatOn=%d\nuninstProt=%d\n",
        g_state.mode, g_state.fails, g_state.lockUntil,
        g_state.forgetDeadline, g_state.formatOn, g_state.uninstProt);
    fclose(f);
}

static const WCHAR *ModeName(int m)
{
    switch (m) {
    case 0: return L"无需解锁";
    case 1: return L"普通模式（仅数字）";
    case 2: return L"加密模式（仅字母）";
    case 3: return L"进阶模式（9位数字+字母+符号）";
    default: return L"密钥模式（500位内任意字符）";
    }
}

/* 模式校验：返回 1=允许该字符 */
static BOOL ModeAllowChar(int mode, wchar_t c)
{
    if (mode == 1) return (c >= L'0' && c <= L'9');
    if (mode == 2) return ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z'));
    return TRUE; /* 3/4 允许任意字符，确认时校验 */
}

static const WCHAR *ModeCheckInput(int mode, const WCHAR *s)
{
    if (mode == 3 && (int)wcslen(s) != 9) return L"进阶模式要求密码恰好 9 位（数字+字母+符号组合）";
    return NULL;
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
    (void)owner;
    wsprintfW(volPath, L"%c:\\", g_dir[0]);
    if (!GetVolumeNameForVolumeMountPointW(volPath, volName, MAX_PATH))
        return FALSE;
    if (GetDriveTypeW(volPath) != DRIVE_REMOVABLE) return FALSE;

    HANDLE hVol = CreateFileW(volPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return FALSE;
    STORAGE_DEVICE_NUMBER sdn; DWORD ret = 0;
    if (!DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                         &sdn, sizeof(sdn), &ret, NULL)) { CloseHandle(hVol); return FALSE; }
    CloseHandle(hVol);

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
            /* 接口路径 → 设备实例 ID（DESIGN.md 实现备注） */
            WCHAR id[512] = L"";
            const WCHAR *q = p + 4;
            const WCHAR *end = wcsrchr(q, L'#');
            if (!end) end = q + wcslen(q);
            size_t n = 0;
            for (; q < end && n < 510; q++, n++) {
                if (q[0] == L'#' && q[1] == L'{') break;
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

/* 格式化兜底（DESIGN.md 第四节，默认关闭，需超级模式开启） */
static void TriggerFormat(HWND wnd)
{
    if (!g_state.formatOn) {
        /* 未开启格式化 → 上限锁定 120 分钟，防无限增长 */
        g_state.lockUntil = (long long)time(NULL) + 7200;
        SaveState();
        SetButtonsEnabled(wnd, FALSE);
        return;
    }
    MessageBoxW(wnd,
        L"⛔ 输错次数已超过安全上限（60 次）！\n\n"
        L"按安全策略，本盘数据即将被清除。\n"
        L"若此前已开启隐藏备份，可事后用恢复工具找回数据。",
        APP_NAME, MB_OK | MB_ICONERROR);
    wchar_t cmd[300];
    wsprintfW(cmd, L"/c format %c: /Q /Y /X", g_dir[0]);
    ShellExecuteW(wnd, L"open", L"format.com", cmd, NULL, SW_HIDE);
    DeleteFileW(g_pwFile);
    DeleteFileW(g_stateFile);
    ExitProcess(0);
}

static void OnWrongPassword(HWND wnd)
{
    time_t now = time(NULL);
    if (now < (time_t)g_state.lockUntil) return;
    g_state.fails++;
    InputClear();
    if (g_state.fails > 60) { TriggerFormat(wnd); return; }
    if (g_state.fails % 5 == 0) {
        /* 递进锁定：每 5 次 → (次数÷5)×10 分钟（DESIGN.md 第四节） */
        g_state.lockUntil = (long long)now + (long long)(g_state.fails / 5) * 600;
        SetButtonsEnabled(wnd, FALSE);
    }
    SaveState();
    InvalidateRect(wnd, NULL, TRUE);
}

static void UnlockSuccess(HWND wnd)
{
    g_state.fails = 0;
    g_state.lockUntil = 0;
    SaveState();
    HookOff();
    MessageBoxW(wnd, L"✔ 密码正确，已解锁！\n\n程序已缩至任务栏托盘待命：\n  · 双击托盘图标可重新锁定\n  · 拔出U盘后程序自动退出",
        APP_NAME, MB_OK | MB_ICONINFORMATION);
    DestroyWindow(wnd);   /* WM_DESTROY 中转入托盘待命 */
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
            SetWindowPos(g_keys[i], NULL,
                x0 + c * (bw + 8), y0 + r * (bh + 8), bw, bh, SWP_NOZORDER);
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

    HFONT f1 = CreateFontW(52, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f2 = CreateFontW(30, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f3 = CreateFontW(36, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");

    if (now < (time_t)g_state.lockUntil) {
        int left = (int)(g_state.lockUntil - now);
        int min = left / 60, sec = left % 60;
        wchar_t buf[128];
        if (min > 0) wsprintfW(buf, L"⛔ 输错次数过多，请等待 %d 分 %d 秒后再试", min, sec);
        else         wsprintfW(buf, L"⛔ 输错次数过多，请等待 %d 秒后再试", sec);
        SetTextColor(dc, RGB(248, 113, 113));
        SelectObject(dc, f1);
        RECT tr = { 0, 60, W, 150 };
        DrawTextW(dc, buf, -1, &tr, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, f1); DeleteObject(f1);
        SelectObject(dc, f2); DeleteObject(f2);
        SelectObject(dc, f3); DeleteObject(f3);
        return;
    }

    SetTextColor(dc, RGB(230, 238, 248));
    SelectObject(dc, f1);
    RECT t1 = { 0, 40, W, 120 };
    DrawTextW(dc, L"此 USB 设备已被锁定", -1, &t1, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SetTextColor(dc, RGB(140, 160, 190));
    SelectObject(dc, f2);
    RECT t2 = { 0, 125, W, 170 };
    DrawTextW(dc, L"请输入解锁密钥", -1, &t2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SetTextColor(dc, RGB(90, 130, 180));
    RECT t4 = { 0, 168, W, 205 };
    wchar_t mbuf[96];
    wsprintfW(mbuf, L"当前解锁模式：%s", ModeName(g_state.mode));
    DrawTextW(dc, mbuf, -1, &t4, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    if (g_state.fails > 0) {
        wchar_t buf[96];
        int lockMin = (g_state.fails / 5) * 10;
        if (lockMin > 0) wsprintfW(buf, L"已累计输错 %d 次 · 再次错满一档将锁定 %d 分钟", g_state.fails, lockMin + 10);
        else             wsprintfW(buf, L"已累计输错 %d 次", g_state.fails);
        SetTextColor(dc, RGB(250, 190, 120));
        RECT t3 = { 0, 205, W, 240 };
        DrawTextW(dc, buf, -1, &t3, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    /* 密码显示区 */
    if (g_hDisplay) {
        wchar_t mask[64];
        RECT dr; GetClientRect(g_hDisplay, &dr);
        POINT pt = { 0, 0 }; MapWindowPoints(g_hDisplay, wnd, &pt, 1);
        OffsetRect(&dr, pt.x, pt.y);
        HBRUSH bb = CreateSolidBrush(RGB(24, 34, 54));
        FillRect(dc, &dr, bb); DeleteObject(bb);
        HBRUSH fb = CreateSolidBrush(RGB(76, 194, 255));
        FrameRect(dc, &dr, fb); DeleteObject(fb);
        SetTextColor(dc, RGB(76, 194, 255));
        SelectObject(dc, f3);
        RECT inner = dr; InflateRect(&inner, -8, -8);
        if (g_inputLen == 0) {
            SetTextColor(dc, RGB(90, 108, 136));
            DrawTextW(dc, L"（屏幕键盘或物理键盘输入均可）", -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        } else if (g_inputLen > 20) {
            wsprintfW(mask, L"●×%d（已输入 %d 位）", g_inputLen, g_inputLen);
            DrawTextW(dc, mask, -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        } else {
            int i;
            for (i = 0; i < g_inputLen && i < 20; i++) mask[i] = L'●';
            mask[i] = 0;
            DrawTextW(dc, mask, -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        }
    }

    SelectObject(dc, f1); DeleteObject(f1);
    SelectObject(dc, f2); DeleteObject(f2);
    SelectObject(dc, f3); DeleteObject(f3);
}

static void ShowLockWindow(void);
static void ShowTrayWindow(void);
static ATOM RegOneClass(WNDPROC proc, const wchar_t *name, HBRUSH bg);

static void EnterStandby(void)
{
    if (g_hTrayWnd) return;
    ShowTrayWindow();
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
        SetTimer(wnd, 2, 500, NULL);
        return 0;
    }
    case WM_TIMER:
        if (wp == 2) {
            SetWindowPos(wnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            if (g_state.lockUntil && time(NULL) >= (time_t)g_state.lockUntil) {
                g_state.lockUntil = 0; SaveState();
                SetButtonsEnabled(wnd, TRUE);
            }
            InvalidateRect(wnd, NULL, TRUE);
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
    case WM_CHAR: {
        /* 物理键盘输入（密钥模式支持任意可见字符） */
        time_t now = time(NULL);
        if (now < (time_t)g_state.lockUntil) return 0;
        wchar_t c = (wchar_t)wp;
        if (c == 8) { InputBack(); return 0; }
        if (c == 13) { SendMessageW(wnd, WM_COMMAND, IDC_CONFIRM, 0); return 0; }
        if (c < 0x20) return 0;
        if (!ModeAllowChar(g_state.mode, c)) return 0;
        InputAppend(c);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        time_t now = time(NULL);
        if (now < (time_t)g_state.lockUntil) return 0;
        if (id == IDC_BACKSPACE) InputBack();
        else if (id == IDC_CONFIRM) {
            if (g_inputLen == 0) return 0;
            const WCHAR *err = ModeCheckInput(g_state.mode, g_input);
            if (err) { MessageBoxW(wnd, err, APP_NAME, MB_ICONWARNING); return 0; }
            WCHAR tmp[MAX_PWD + 1]; wcscpy(tmp, g_input);
            if (CheckPassword(tmp)) UnlockSuccess(wnd);
            else OnWrongPassword(wnd);
        }
        else if (id == IDC_CANCEL) {
            if (MessageBoxW(wnd, L"确定取消并弹出 USB 设备吗？\n（程序将关闭并安全弹出U盘）",
                    APP_NAME, MB_YESNO | MB_ICONQUESTION) == IDYES) {
                HookOff();
                wchar_t volp[8];
                wsprintfW(volp, L"%c:\\", g_dir[0]);
                if (!EjectUsb(wnd) && GetDriveTypeW(volp) == DRIVE_REMOVABLE)
                    MessageBoxW(wnd, L"弹出失败：可能有文件正在被占用，请手动弹出。",
                        APP_NAME, MB_OK | MB_ICONWARNING);
                ExitProcess(0);
            }
        }
        else if (id >= IDC_KEYBASE && id < IDC_KEYBASE + g_keyCount) {
            int ch = g_keyChar[id - IDC_KEYBASE];
            if (ch == -1) InputBack();
            else if (ModeAllowChar(g_state.mode, (wchar_t)ch)) InputAppend((wchar_t)ch);
        }
        return 0;
    }
    case WM_DESTROY:
        KillTimer(wnd, 2);
        if (g_hLockWnd == wnd) {
            g_hLockWnd = NULL;
            HookOff();
            EnterStandby();   /* 解锁后进入托盘待命 */
        }
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

/* ---------------- 托盘待命 ---------------- */
#define WM_TRAY (WM_APP + 1)
#define IDM_RELOCK  201
#define IDM_OPEN    202
#define IDM_EXIT    203

static BOOL VerifyPasswordDialog(HWND owner, const WCHAR *title);

static void AddTrayIcon(HWND wnd, BOOL add)
{
    NOTIFYICONDATAW nid = { sizeof(nid) };
    nid.hWnd = wnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wcscpy(nid.szTip, APP_NAME L" 待命中（双击重新锁定）");
    if (add) Shell_NotifyIconW(NIM_ADD, &nid);
    else     Shell_NotifyIconW(NIM_DELETE, &nid);
}

static LRESULT CALLBACK TrayProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        AddTrayIcon(wnd, TRUE);
        SetTimer(wnd, 3, 2000, NULL);   /* U盘拔出监视（DESIGN.md 第五节） */
        return 0;
    case WM_TIMER:
        if (wp == 3) {
            wchar_t vol[8];
            wsprintfW(vol, L"%c:\\", g_dir[0]);
            int t = GetDriveTypeW(vol);
            if (t != DRIVE_REMOVABLE && t != DRIVE_FIXED) {
                /* 盘符消失（U盘被拔）→ 自动退出，不留后台 */
                AddTrayIcon(wnd, FALSE);
                ExitProcess(0);
            }
        }
        return 0;
    case WM_TRAY:
        if (lp == WM_LBUTTONDBLCLK) {
            AddTrayIcon(wnd, FALSE);
            DestroyWindow(wnd);
            ShowLockWindow();
        } else if (lp == WM_RBUTTONUP) {
            HMENU m = CreatePopupMenu();
            AppendMenuW(m, MF_STRING, IDM_RELOCK, L"重新锁定");
            AppendMenuW(m, MF_STRING, IDM_OPEN,   L"打开本盘");
            AppendMenuW(m, MF_SEPARATOR, 0, NULL);
            AppendMenuW(m, MF_STRING, IDM_EXIT,   L"退出程序");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(wnd);
            int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, wnd, NULL);
            DestroyMenu(m);
            if (cmd == IDM_RELOCK) {
                WCHAR hex[65];
                if (!ReadHexFile(g_pwFile, hex)) {
                    MessageBoxW(wnd, L"未找到密码文件，请先运行设置模式创建密码。", APP_NAME, MB_ICONWARNING);
                    return 0;
                }
                AddTrayIcon(wnd, FALSE);
                DestroyWindow(wnd);
                ShowLockWindow();
            } else if (cmd == IDM_OPEN) {
                ShellExecuteW(wnd, L"open", g_dir, NULL, NULL, SW_SHOWNORMAL);
            } else if (cmd == IDM_EXIT) {
                /* 卸载保护第一层：退出需密码（DESIGN.md 第七节） */
                if (g_state.uninstProt && !VerifyPasswordDialog(wnd, L"退出 USB_safely 需要密码确认"))
                    return 0;
                AddTrayIcon(wnd, FALSE);
                DestroyWindow(wnd);
                PostQuitMessage(0);
            }
        }
        return 0;
    case WM_DESTROY:
        KillTimer(wnd, 3);
        if (g_hTrayWnd == wnd) g_hTrayWnd = NULL;
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

/* ---------------- 密码确认小窗 ---------------- */
static HWND g_hVerifyWnd = NULL;
static HWND g_hVerifyEdit = NULL;
static BOOL g_verifyOk = FALSE;

static LRESULT CALLBACK VerifyProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT fn = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        CreateWindowW(L"STATIC", L"请输入密码：", WS_CHILD|WS_VISIBLE, 20, 20, 340, 24, wnd, NULL, g_hInst, NULL);
        g_hVerifyEdit = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            20, 52, 340, 30, wnd, (HMENU)(INT_PTR)101, g_hInst, NULL);
        HWND ok = CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            100, 100, 80, 32, wnd, (HMENU)(INT_PTR)102, g_hInst, NULL);
        HWND no = CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            200, 100, 80, 32, wnd, (HMENU)(INT_PTR)103, g_hInst, NULL);
        SendMessageW(g_hVerifyEdit, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(ok, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(no, WM_SETFONT, (WPARAM)fn, TRUE);
        DeleteObject(fn);
        SetFocus(g_hVerifyEdit);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == 102) {
            wchar_t buf[MAX_PWD + 1];
            GetWindowTextW(g_hVerifyEdit, buf, MAX_PWD + 1);
            g_verifyOk = CheckPassword(buf);
            DestroyWindow(wnd);
        } else if (id == 103) {
            g_verifyOk = FALSE;
            DestroyWindow(wnd);
        }
        return 0;
    }
    case WM_CLOSE:
        g_verifyOk = FALSE;
        DestroyWindow(wnd);
        return 0;
    case WM_DESTROY:
        g_hVerifyWnd = NULL;
        PostQuitMessage(0);   /* 结束 VerifyPasswordDialog 的局部消息循环 */
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

static BOOL VerifyPasswordDialog(HWND owner, const WCHAR *title)
{
    (void)owner;
    g_verifyOk = FALSE;
    CreateWindowW(L"USBsafelyVerify", title,
        (WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX)) | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 190, NULL, NULL, g_hInst, NULL);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return g_verifyOk;
}

/* ---------------- 超级模式窗口 ---------------- */
static int g_supVerified = 0;

static void DoSuperReset(HWND wnd)
{
    wchar_t nw1[MAX_PWD + 1], nw2[MAX_PWD + 1];
    GetWindowTextW(g_hSupNew1, nw1, MAX_PWD + 1);
    GetWindowTextW(g_hSupNew2, nw2, MAX_PWD + 1);
    if (!nw1[0]) { MessageBoxW(wnd, L"新密码不能为空", APP_NAME, MB_ICONWARNING); return; }
    if (wcscmp(nw1, nw2) != 0) { MessageBoxW(wnd, L"两次输入的新密码不一致", APP_NAME, MB_ICONWARNING); return; }
    const WCHAR *err = ModeCheckInput(g_state.mode, nw1);
    if (err) { MessageBoxW(wnd, err, APP_NAME, MB_ICONWARNING); return; }
    WCHAR hex[65];
    if (Sha256Hex(nw1, hex) && SavePasswordHash(hex)) {
        g_state.fails = 0; g_state.lockUntil = 0; SaveState();
        MessageBoxW(wnd, L"锁屏密码已重置！", APP_NAME, MB_OK | MB_ICONINFORMATION);
        SetWindowTextW(g_hSupNew1, L""); SetWindowTextW(g_hSupNew2, L"");
    } else
        MessageBoxW(wnd, L"写入失败", APP_NAME, MB_ICONERROR);
}

static void DoSuperForget(HWND wnd)
{
    int sel = (int)SendMessageW(g_hSupForget, CB_GETCURSEL, 0, 0);
    long long now = (long long)time(NULL);
    static const int days[4] = { 0, 1, 30, 365 };
    g_state.forgetDeadline = (sel > 0 && sel <= 3) ? now + (long long)days[sel] * 86400 : 0;
    SaveState();
    MessageBoxW(wnd, L"已更新忘记密码重置期限", APP_NAME, MB_OK | MB_ICONINFORMATION);
}

static void DoSuperFormat(HWND wnd)
{
    g_state.formatOn = (SendMessageW(g_hSupFmt, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
    SaveState();
    MessageBoxW(wnd, g_state.formatOn
        ? L"已开启格式化兜底（错61次起清盘，请务必先做隐藏备份）"
        : L"已关闭格式化兜底（改为上限锁定120分钟）",
        APP_NAME, MB_OK | MB_ICONINFORMATION);
}

static LRESULT CALLBACK SuperProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT f  = CreateFontW(19, 0, 0, 0, FW_BOLD,   0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        HFONT fn = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        CreateWindowW(L"STATIC", L"超级模式 · 第一步：验证恢复密码",
            WS_CHILD|WS_VISIBLE, 20, 16, 390, 26, wnd, NULL, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"恢复密码：", WS_CHILD|WS_VISIBLE, 20, 55, 90, 22, wnd, NULL, g_hInst, NULL);
        g_hRecEdit = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            115, 52, 220, 28, wnd, (HMENU)(INT_PTR)201, g_hInst, NULL);
        HWND bv = CreateWindowW(L"BUTTON", L"验证", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            20, 92, 110, 32, wnd, (HMENU)(INT_PTR)202, g_hInst, NULL);
        /* 第二步面板（验证成功后整体显示，子控件随面板隐藏） */
        g_hSupPanel = CreateWindowW(L"STATIC", L"",
            WS_CHILD, 10, 135, 415, 250, wnd, NULL, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 重置锁屏密码 ──", WS_CHILD|WS_VISIBLE, 12, 12, 220, 22, g_hSupPanel, NULL, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"新密码：", WS_CHILD|WS_VISIBLE, 12, 42, 90, 22, g_hSupPanel, NULL, g_hInst, NULL);
        g_hSupNew1 = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            105, 40, 220, 26, g_hSupPanel, (HMENU)(INT_PTR)203, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"再输入：", WS_CHILD|WS_VISIBLE, 12, 74, 90, 22, g_hSupPanel, NULL, g_hInst, NULL);
        g_hSupNew2 = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            105, 72, 220, 26, g_hSupPanel, (HMENU)(INT_PTR)204, g_hInst, NULL);
        CreateWindowW(L"BUTTON", L"重置密码", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            105, 105, 120, 30, g_hSupPanel, (HMENU)(INT_PTR)205, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 忘记密码重置期限 ──", WS_CHILD|WS_VISIBLE, 12, 145, 220, 22, g_hSupPanel, NULL, g_hInst, NULL);
        g_hSupForget = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 12, 170, 200, 120, g_hSupPanel, (HMENU)(INT_PTR)206, g_hInst, NULL);
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"关闭");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"24 小时后自动重置");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"30 天后自动重置");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"365 天后自动重置");
        CreateWindowW(L"BUTTON", L"保存期限", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            230, 170, 110, 28, g_hSupPanel, (HMENU)(INT_PTR)207, g_hInst, NULL);
        g_hSupFmt = CreateWindowW(L"BUTTON", L"开启格式化兜底（错61次起清盘，危险！）",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 12, 208, 390, 24, g_hSupPanel, (HMENU)(INT_PTR)208, g_hInst, NULL);
        SendMessageW(g_hRecEdit, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(bv, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hSupNew1, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hSupNew2, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hSupForget, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hSupFmt, WM_SETFONT, (WPARAM)fn, TRUE);
        DeleteObject(f); DeleteObject(fn);
        SendMessageW(g_hSupFmt, BM_SETCHECK, g_state.formatOn ? BST_CHECKED : BST_UNCHECKED, 0);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp), ev = HIWORD(wp);
        if (id == 202 && ev == BN_CLICKED) {
            wchar_t rec[MAX_PWD + 1];
            GetWindowTextW(g_hRecEdit, rec, MAX_PWD + 1);
            WCHAR rhex[65];
            if (!ReadHexFile(g_recFile, rhex)) {
                /* 首次进入超级模式：本次输入将成为恢复密码 */
                if ((int)wcslen(rec) < 4) {
                    MessageBoxW(wnd, L"恢复密码至少 4 位。请输入后再次点击「验证」即可设置。",
                        APP_NAME, MB_ICONINFORMATION);
                    return 0;
                }
                if (MessageBoxW(wnd,
                        L"检测到尚未设置恢复密码。\n本次输入将直接设为恢复密码（请牢记，\n忘记恢复密码=备份永久不可用）。继续吗？",
                        APP_NAME, MB_YESNO | MB_ICONQUESTION) != IDYES)
                    return 0;
                WCHAR nh[65];
                if (!Sha256Hex(rec, nh) || !_wfopen(g_recFile, L"w")) {
                    /* 写入 */
                    FILE *f = _wfopen(g_recFile, L"w");
                    if (!f) { MessageBoxW(wnd, L"写入失败", APP_NAME, MB_ICONERROR); return 0; }
                    fwprintf(f, L"%s\n", nh);
                    fclose(f);
                }
                MessageBoxW(wnd, L"恢复密码已设置，已进入超级模式。", APP_NAME, MB_OK | MB_ICONINFORMATION);
                g_supVerified = 1;
                ShowWindow(g_hSupPanel, SW_SHOW);
                return 0;
            }
            if (!CheckRecovery(rec)) {
                MessageBoxW(wnd, L"恢复密码错误！", APP_NAME, MB_ICONWARNING);
                return 0;
            }
            g_supVerified = 1;
            ShowWindow(g_hSupPanel, SW_SHOW);
            MessageBoxW(wnd, L"恢复密码验证成功，已进入超级模式。", APP_NAME, MB_OK | MB_ICONINFORMATION);
        }
        else if (id == 205 && ev == BN_CLICKED && g_supVerified) DoSuperReset(wnd);
        else if (id == 207 && ev == BN_CLICKED && g_supVerified) DoSuperForget(wnd);
        else if (id == 208 && ev == BN_CLICKED && g_supVerified) DoSuperFormat(wnd);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

static void ShowSuperWindow(void)
{
    RegOneClass(SuperProc, L"USBsafelySuper", CreateSolidBrush(RGB(28, 32, 40)));
    CreateWindowW(L"USBsafelySuper", L"USB_safely 超级模式",
        (WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX)) | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 450, 430, NULL, NULL, g_hInst, NULL);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
}

/* ---------------- 设置窗口 ---------------- */
#define IDC_EDOLD    3001
#define IDC_EDNEW    3002
#define IDC_EDNEW2   3003
#define IDC_BTNCHG   3004
#define IDC_VERLBL   3005
#define IDC_MODECMB  3006
#define IDC_BTNSAVE  3007

static void DoChangePassword(HWND wnd)
{
    wchar_t old[MAX_PWD + 1], nw1[MAX_PWD + 1], nw2[MAX_PWD + 1];
    GetWindowTextW(g_hOld,  old,  MAX_PWD + 1);
    GetWindowTextW(g_hNew,  nw1,  MAX_PWD + 1);
    GetWindowTextW(g_hNew2, nw2,  MAX_PWD + 1);
    if (!nw1[0]) { MessageBoxW(wnd, L"密码不能为空", APP_NAME, MB_ICONWARNING); return; }
    if (wcscmp(nw1, nw2) != 0) { MessageBoxW(wnd, L"两次输入的新密码不一致", APP_NAME, MB_ICONWARNING); return; }
    WCHAR ohex[65];
    if (ReadHexFile(g_pwFile, ohex)) {           /* 已有密码 → 验证旧密码 */
        WCHAR ihex[65];
        Sha256Hex(old, ihex);
        if (_wcsicmp(ihex, ohex) != 0) { MessageBoxW(wnd, L"旧密码错误！", APP_NAME, MB_ICONWARNING); return; }
    }
    const WCHAR *err = ModeCheckInput(g_state.mode, nw1);
    if (err) { MessageBoxW(wnd, err, APP_NAME, MB_ICONWARNING); return; }
    WCHAR hex[65];
    if (Sha256Hex(nw1, hex) && SavePasswordHash(hex)) {
        MessageBoxW(wnd, L"密码修改成功！", APP_NAME, MB_OK | MB_ICONINFORMATION);
        SetWindowTextW(g_hOld, L""); SetWindowTextW(g_hNew, L""); SetWindowTextW(g_hNew2, L"");
    } else
        MessageBoxW(wnd, L"写入密码文件失败", APP_NAME, MB_ICONERROR);
}

static void DoSaveMode(HWND wnd)
{
    int sel = (int)SendMessageW(g_hModeCombo, CB_GETCURSEL, 0, 0);
    if (sel < 0 || sel > 4) return;
    g_state.mode = sel;
    SaveState();
    MessageBoxW(wnd, L"解锁模式已更新（立即生效）", APP_NAME, MB_OK | MB_ICONINFORMATION);
}

static LRESULT CALLBACK SetupProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT f  = CreateFontW(19, 0, 0, 0, FW_BOLD,   0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        HFONT fn = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        CreateWindowW(L"STATIC", L"── 解锁模式 ──", WS_CHILD|WS_VISIBLE, 30, 18, 340, 26, wnd, NULL, g_hInst, NULL);
        g_hModeCombo = CreateWindowW(L"COMBOBOX", L"", WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST,
            30, 48, 250, 140, wnd, (HMENU)(INT_PTR)IDC_MODECMB, g_hInst, NULL);
        for (int i = 0; i <= 4; i++)
            SendMessageW(g_hModeCombo, CB_ADDSTRING, 0, (LPARAM)ModeName(i));
        SendMessageW(g_hModeCombo, CB_SETCURSEL, g_state.mode, 0);
        HWND sm = CreateWindowW(L"BUTTON", L"应用模式", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            295, 46, 110, 30, wnd, (HMENU)(INT_PTR)IDC_BTNSAVE, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 修改密码 ──", WS_CHILD|WS_VISIBLE, 30, 92, 340, 26, wnd, NULL, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"旧密码：", WS_CHILD|WS_VISIBLE, 30, 128, 90, 22, wnd, NULL, g_hInst, NULL);
        g_hOld = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            125, 125, 240, 28, wnd, (HMENU)(INT_PTR)IDC_EDOLD, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"新密码：", WS_CHILD|WS_VISIBLE, 30, 163, 90, 22, wnd, NULL, g_hInst, NULL);
        g_hNew = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            125, 160, 240, 28, wnd, (HMENU)(INT_PTR)IDC_EDNEW, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"再输入：", WS_CHILD|WS_VISIBLE, 30, 198, 90, 22, wnd, NULL, g_hInst, NULL);
        g_hNew2 = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            125, 195, 240, 28, wnd, (HMENU)(INT_PTR)IDC_EDNEW2, g_hInst, NULL);
        HWND chg = CreateWindowW(L"BUTTON", L"修改密码", WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            125, 232, 160, 34, wnd, (HMENU)(INT_PTR)IDC_BTNCHG, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 关于程序 ──", WS_CHILD|WS_VISIBLE, 30, 280, 340, 26, wnd, NULL, g_hInst, NULL);
        g_hVerLabel = CreateWindowW(L"BUTTON", L"版本 " APP_VER L"（连点5下开启超级模式）",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|BS_LEFT, 30, 310, 355, 34, wnd, (HMENU)(INT_PTR)IDC_VERLBL, g_hInst, NULL);
        wchar_t about[256];
        wsprintfW(about, L"USB_safely — U盘锁\n制作团队：%s\n保护 U 盘个人文件，防止别人翻看", TEAM_NAME);
        g_hAbout = CreateWindowW(L"STATIC", about, WS_CHILD|WS_VISIBLE, 30, 355, 380, 90, wnd, NULL, g_hInst, NULL);
        SendMessageW(g_hModeCombo, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(sm, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hOld, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hNew, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(g_hNew2, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(chg, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hVerLabel, WM_SETFONT, (WPARAM)f, TRUE);
        SendMessageW(g_hAbout, WM_SETFONT, (WPARAM)fn, TRUE);
        DeleteObject(f); DeleteObject(fn);
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp), ev = HIWORD(wp);
        if (id == IDC_BTNCHG && ev == BN_CLICKED) DoChangePassword(wnd);
        else if (id == IDC_BTNSAVE && ev == BN_CLICKED) DoSaveMode(wnd);
        else if (id == IDC_VERLBL && ev == BN_CLICKED) {
            static int clicks = 0;
            clicks++;
            if (clicks >= 5) { clicks = 0; ShowSuperWindow(); }
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

/* ---------------- 窗口调度 ---------------- */
static ATOM RegOneClass(WNDPROC proc, const wchar_t *name, HBRUSH bg)
{
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = proc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = bg ? bg : CreateSolidBrush(RGB(12, 18, 32));
    wc.lpszClassName = name;
    return RegisterClassW(&wc);
}

static void ShowLockWindow(void)
{
    HookOn();
    RegOneClass(LockProc, L"USBsafelyLock", NULL);
    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);
    g_hLockWnd = CreateWindowExW(WS_EX_TOPMOST, L"USBsafelyLock", APP_NAME,
        WS_POPUP | WS_VISIBLE, 0, 0, sx, sy, NULL, NULL, g_hInst, NULL);
    SetFocus(g_hLockWnd);
}

static void ShowTrayWindow(void)
{
    RegOneClass(TrayProc, L"USBsafelyTray", CreateSolidBrush(RGB(28, 32, 40)));
    g_hTrayWnd = CreateWindowW(L"USBsafelyTray", APP_NAME L" 待命",
        WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
        NULL, NULL, g_hInst, NULL);
}

/* ---------------- 入口 ---------------- */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE prev, LPWSTR cmd, int show)
{
    (void)prev; (void)show;
    g_hInst = hInst;

    /* 安装目录 = exe 所在目录（U盘根目录或硬盘安装目录） */
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wcscpy(g_dir, exe);
    wchar_t *sl = wcsrchr(g_dir, L'\\');
    if (sl) *sl = 0;

    wchar_t pwDir[MAX_PATH];
    wsprintfW(pwDir, L"%s\\password", g_dir);
    CreateDirectoryW(pwDir, NULL);
    wsprintfW(g_pwFile,    L"%s\\pw.sf",       pwDir);
    wsprintfW(g_stateFile, L"%s\\state.sf",    pwDir);
    wsprintfW(g_recFile,   L"%s\\recovery.sf", pwDir);

    LoadState();

    BOOL setupMode = (cmd && (wcsstr(cmd, L"setup") || wcsstr(cmd, L"config")));

    /* 忘记密码期限已到 → 自动重置（DESIGN.md 第八节） */
    WCHAR hex[65];
    if (g_state.forgetDeadline && (long long)time(NULL) >= g_state.forgetDeadline && ReadHexFile(g_pwFile, hex)) {
        DeleteFileW(g_pwFile);
        g_state.forgetDeadline = 0; g_state.fails = 0; g_state.lockUntil = 0;
        SaveState();
        MessageBoxW(NULL, L"忘记密码重置期限已到，密码已自动清除。\n请重新设置新密码。",
            APP_NAME, MB_OK | MB_ICONINFORMATION);
    }

    if (!setupMode && !ReadHexFile(g_pwFile, hex)) {
        /* 首次使用：引导进入设置 */
        MessageBoxW(NULL,
            L"检测到首次使用：还没有密码文件。\n\n请在接下来的窗口中设置密码，\n"
            L"设置完成关闭窗口后程序进入待命/锁定状态。",
            APP_NAME, MB_OK | MB_ICONINFORMATION);
        setupMode = TRUE;
    }

    RegOneClass(SetupProc,  L"USBsafelySetup",  CreateSolidBrush(RGB(28, 32, 40)));
    RegOneClass(VerifyProc, L"USBsafelyVerify", CreateSolidBrush(RGB(28, 32, 40)));

    if (setupMode) {
        CreateWindowW(L"USBsafelySetup", L"USB_safely 设置",
            (WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX)) | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 445, 500, NULL, NULL, hInst, NULL);
    } else if (g_state.mode == 0) {
        ShowTrayWindow();               /* 无需解锁模式 → 直接待命 */
    } else {
        ShowLockWindow();
    }

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
