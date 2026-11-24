/* =====================================================================
 * USB_safely — U盘锁 v2.0.0 主程序
 * 设计来源：USB_safely 设计方案（APPLE_INT）· 见仓库 DESIGN.md
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
#include <windowsx.h>
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
#define APP_VER      L"V2.1.1.5"
#define TEAM_NAME    L"APPLE_INT · Geek-Hub"
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

static BOOL WriteHexFile(const WCHAR *file, const WCHAR hex[65])
{
    /* 哈希是纯 ASCII，按字节写，避免宽流 %s 的未定义行为（会写出垃圾内容） */
    FILE *f = _wfopen(file, L"wb");
    if (!f) return FALSE;
    char b[66];
    for (int i = 0; i < 64; i++) b[i] = (char)hex[i];
    b[64] = '\n'; b[65] = 0;
    BOOL ok = fwrite(b, 1, 65, f) == 65;
    fclose(f);
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
    /* v2.1.1：原子化写入——临时文件 → 读回校验 → 原子替换，
       杜绝写一半/新旧内容混合导致"输什么都不对"的损坏密码文件 */
    wchar_t tmp[1100];
    wsprintfW(tmp, L"%s.tmp", g_pwFile);
    if (!WriteHexFile(tmp, hex)) return FALSE;
    WCHAR back[65];
    if (!ReadHexFile(tmp, back) || _wcsicmp(back, hex) != 0) {
        DeleteFileW(tmp);
        return FALSE;
    }
    if (!MoveFileExW(tmp, g_pwFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp);
        return FALSE;
    }
    /* 终验：正式文件读回必须等于刚写的哈希 */
    if (!ReadHexFile(g_pwFile, back) || _wcsicmp(back, hex) != 0) return FALSE;
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

/* v2.1.1：按新密码内容自动匹配解锁模式，杜绝"字母密码+数字模式"锁死 */
static int DetectMode(const WCHAR *s)
{
    BOOL dig = TRUE, let = TRUE;
    for (const WCHAR *p = s; *p; p++) {
        if (*p < L'0' || *p > L'9') dig = FALSE;
        if (!((*p >= L'A' && *p <= L'Z') || (*p >= L'a' && *p <= L'z'))) let = FALSE;
    }
    if (dig) return 1;                      /* 全数字 → 普通模式 */
    if (let) return 2;                      /* 全字母 → 加密模式 */
    if ((int)wcslen(s) == 9) return 3;      /* 9 位混合 → 进阶模式 */
    return 4;                               /* 其他 → 密钥模式 */
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
    if (!ModeAllowChar(g_state.mode, c)) return;   /* 模式过滤兜底（v2.0.2） */
    if (g_inputLen < MAX_PWD) { g_input[g_inputLen++] = c; g_input[g_inputLen] = 0; InvalidateRect(g_hLockWnd, NULL, FALSE); }
}
static void InputBack(void)
{
    if (g_inputLen > 0) { g_inputLen--; g_input[g_inputLen] = 0; InvalidateRect(g_hLockWnd, NULL, FALSE); }
}
static void InputClear(void)
{
    g_inputLen = 0; g_input[0] = 0; InvalidateRect(g_hLockWnd, NULL, FALSE);
}

/* ---------------- v2.1.0 现代化 UI：自绘控件 + 双缓冲 ---------------- */
#define CLR_BG_TOP     RGB(22, 28, 46)    /* 背景渐变顶部（深蓝，非纯黑） */
#define CLR_BG_BOTTOM  RGB(48, 38, 78)    /* 背景渐变底部（紫） */
#define CLR_ACCENT     RGB(76, 194, 255)  /* 主色 #4CC2FF（与 Geek-Hub 同源） */
#define CLR_KEY_FILL   RGB(36, 46, 70)
#define CLR_KEY_HOVER  RGB(54, 70, 104)
#define CLR_KEY_EDGE   RGB(66, 86, 124)
#define CLR_TEXT       RGB(232, 240, 252)
#define CLR_SUBTEXT    RGB(138, 156, 190)
#define CLR_DANGER     RGB(248, 113, 113)
#define CLR_WARN       RGB(250, 190, 120)

typedef struct { RECT r; int ch; } VKEY;          /* ch=-1 为退格 */
static VKEY  g_vk[48];
static int   g_vkCount = 0;
static RECT  g_rcDisplay, g_rcBack, g_rcConfirm, g_rcCancel;
static int   g_hoverKey = -1, g_hoverBtn = 0;     /* 0无 1确认 2取消 3退格 */

/* 垂直渐变填充（msimg32） */
static void FillVGrad(HDC dc, RECT rc, COLORREF c1, COLORREF c2)
{
    TRIVERTEX tv[2] = {
        { rc.left,  rc.top,    (USHORT)(GetRValue(c1) << 8), (USHORT)(GetGValue(c1) << 8), (USHORT)(GetBValue(c1) << 8), 0 },
        { rc.right, rc.bottom, (USHORT)(GetRValue(c2) << 8), (USHORT)(GetGValue(c2) << 8), (USHORT)(GetBValue(c2) << 8), 0 }
    };
    GRADIENT_RECT gr = { 0, 1 };
    GradientFill(dc, tv, 2, &gr, 1, GRADIENT_FILL_RECT_V);
}

/* 圆角矩形（填充+描边） */
static void RoundedBox(HDC dc, RECT r, int rad, COLORREF fill, COLORREF border, int penw)
{
    HBRUSH b = (fill == -1) ? (HBRUSH)GetStockObject(NULL_BRUSH) : CreateSolidBrush(fill);
    HPEN  p = (border == -1) ? (HPEN)GetStockObject(NULL_PEN) : CreatePen(PS_SOLID, penw, border);
    HBRUSH ob = (HBRUSH)SelectObject(dc, b);
    HPEN  op = (HPEN)SelectObject(dc, p);
    RoundRect(dc, r.left, r.top, r.right + 1, r.bottom + 1, rad, rad);
    SelectObject(dc, ob); SelectObject(dc, op);
    if (fill != -1) DeleteObject(b);
    if (border != -1) DeleteObject(p);
}

/* v2.1.0 共用：现代窗口消息（渐变背景 / 透明文字 / 深色输入框 / 自绘按钮） */
static HBRUSH g_hEditBrush = NULL;
static LRESULT ModernErase(HWND wnd, HDC dc)
{
    RECT rc; GetClientRect(wnd, &rc);
    FillVGrad(dc, rc, RGB(26, 32, 52), RGB(44, 38, 68));
    return 1;
}
static LRESULT ModernStatic(HDC dc)
{
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, CLR_TEXT);
    return (LRESULT)GetStockObject(NULL_BRUSH);
}
static LRESULT ModernEdit(HDC dc)
{
    if (!g_hEditBrush) g_hEditBrush = CreateSolidBrush(RGB(30, 38, 60));
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, CLR_TEXT);
    return (LRESULT)g_hEditBrush;
}
static BOOL ModernBtnDraw(DRAWITEMSTRUCT *dis, COLORREF fill, COLORREF border, COLORREF textc)
{
    BOOL down = (dis->itemState & ODS_SELECTED) != 0;
    BOOL off  = (dis->itemState & ODS_DISABLED)  != 0;
    RoundedBox(dis->hDC, dis->rcItem, 14,
               off ? RGB(30, 36, 54) : (down ? RGB(22, 28, 46) : fill),
               off ? RGB(44, 52, 74) : border, 1);
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, off ? RGB(80, 92, 116) : textc);
    HFONT f = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT of = (HFONT)SelectObject(dis->hDC, f);
    WCHAR txt[96]; GetWindowTextW(dis->hwndItem, txt, 96);
    DrawTextW(dis->hDC, txt, -1, &dis->rcItem, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dis->hDC, of);
    DeleteObject(f);
    return TRUE;
}

/* 格式化兜底（DESIGN.md 第四节，默认关闭，需超级模式开启） */
static void TriggerFormat(HWND wnd)
{
    if (!g_state.formatOn) {
        /* 未开启格式化 → 上限锁定 120 分钟，防无限增长 */
        g_state.lockUntil = (long long)time(NULL) + 7200;
        SaveState();
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

/* 计算锁屏全部自绘元素的布局（按键按解锁模式过滤，退格键全局唯一） */
static void BuildLockLayout(HWND wnd)
{
    RECT rc; GetClientRect(wnd, &rc);
    int W = rc.right, H = rc.bottom;

    /* 收集当前模式允许的字符键 */
    int chars[40], n = 0;
    for (int r = 0; r < 4; r++) {
        int len = (int)wcslen(ROWS[r]);
        for (int c = 0; c < len; c++)
            if (ModeAllowChar(g_state.mode, ROWS[r][c]) && n < 40)
                chars[n++] = ROWS[r][c];
    }

    int cols = n > 10 ? 10 : (n > 0 ? n : 1);
    int rows = (n + cols - 1) / cols;
    int gap = 10;
    int kbW = W < 820 ? W - 60 : 760;
    int kbH = rows * 58 + (rows - 1) * gap;
    if (kbH > H / 2) { kbH = H / 2; }
    int bw = (kbW - (cols - 1) * gap) / cols;
    int bh = kbH / rows - gap;
    if (bh > 52) bh = 52;
    int x0 = (W - kbW) / 2;
    int y0 = H - kbH - 26;

    g_vkCount = 0;
    for (int i = 0; i < n; i++) {
        int r = i / cols, c = i % cols;
        g_vk[g_vkCount].r.left   = x0 + c * (bw + gap);
        g_vk[g_vkCount].r.top    = y0 + r * (bh + gap);
        g_vk[g_vkCount].r.right  = g_vk[g_vkCount].r.left + bw;
        g_vk[g_vkCount].r.bottom = g_vk[g_vkCount].r.top + bh;
        g_vk[g_vkCount].ch = chars[i];
        g_vkCount++;
    }

    /* 密码显示框 + 退格键（显示框右侧） */
    int dispH = 52;
    SetRect(&g_rcDisplay, x0, y0 - dispH - 16, x0 + kbW - 66, y0 - 16);
    SetRect(&g_rcBack,    x0 + kbW - 58, y0 - dispH - 16, x0 + kbW, y0 - 16);

    /* 确认 / 取消按钮 */
    int btnY = g_rcDisplay.top - 62, btnW = 190, btnH = 46;
    int totalW = btnW * 2 + 24;
    int bx = (W - totalW) / 2;
    SetRect(&g_rcConfirm, bx, btnY, bx + btnW, btnY + btnH);
    SetRect(&g_rcCancel,  bx + btnW + 24, btnY, bx + btnW * 2 + 24, btnY + btnH);
}

/* 命中测试：返回键索引；按钮用 g_hoverBtn（1确认 2取消 3退格） */
static int HitKey(int x, int y)
{
    POINT pt = { x, y };
    for (int i = 0; i < g_vkCount; i++)
        if (PtInRect(&g_vk[i].r, pt)) return i;
    if (PtInRect(&g_rcBack, pt))    return -2;
    if (PtInRect(&g_rcConfirm, pt)) return -3;
    if (PtInRect(&g_rcCancel, pt))  return -4;
    return -1;
}

static void PaintLock(HWND wnd, HDC dc, int W, int H)
{
    SetBkMode(dc, TRANSPARENT);
    FillVGrad(dc, (RECT){ 0, 0, W, H }, CLR_BG_TOP, CLR_BG_BOTTOM);

    time_t now = time(NULL);
    BOOL lockedUI = now < (time_t)g_state.lockUntil;

    HFONT f1 = CreateFontW(46, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f2 = CreateFontW(24, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT f3 = CreateFontW(30, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT fk = CreateFontW(20, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT fb = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");

    /* 顶部发光标题条 */
    SelectObject(dc, f1);
    SetTextColor(dc, CLR_TEXT);
    RECT t1 = { 0, 36, W, 96 };
    DrawTextW(dc, L"此 USB 设备已被锁定", -1, &t1, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dc, f2);
    SetTextColor(dc, CLR_SUBTEXT);
    RECT t2 = { 0, 100, W, 136 };
    DrawTextW(dc, L"请输入解锁密钥以继续访问", -1, &t2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SetTextColor(dc, CLR_ACCENT);
    RECT t4 = { 0, 140, W, 172 };
    wchar_t mbuf[96];
    wsprintfW(mbuf, L"●  当前解锁模式：%s", ModeName(g_state.mode));
    DrawTextW(dc, mbuf, -1, &t4, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    if (g_state.fails > 0 && !lockedUI) {
        wchar_t buf[96];
        int lockMin = (g_state.fails / 5) * 10;
        if (lockMin > 0) wsprintfW(buf, L"已累计输错 %d 次 · 再次错满一档将锁定 %d 分钟", g_state.fails, lockMin + 10);
        else             wsprintfW(buf, L"已累计输错 %d 次", g_state.fails);
        SetTextColor(dc, CLR_WARN);
        RECT t3 = { 0, 176, W, 208 };
        DrawTextW(dc, buf, -1, &t3, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    if (lockedUI) {
        /* 锁定倒计时：遮罩提示 + 全部控件置灰 */
        int left = (int)(g_state.lockUntil - now);
        int min = left / 60, sec = left % 60;
        wchar_t buf[128];
        if (min > 0) wsprintfW(buf, L"⛔ 输错次数过多，请等待 %d 分 %d 秒后再试", min, sec);
        else         wsprintfW(buf, L"⛔ 输错次数过多，请等待 %d 秒后再试", sec);
        SetTextColor(dc, CLR_DANGER);
        SelectObject(dc, f3);
        RECT tr = { 0, H / 2 - 60, W, H / 2 };
        DrawTextW(dc, buf, -1, &tr, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, f2);
        SetTextColor(dc, CLR_SUBTEXT);
        RECT tr2 = { 0, H / 2, W, H / 2 + 34 };
        DrawTextW(dc, L"为防止暴力破解，键盘已暂时冻结", -1, &tr2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

        for (int i = 0; i < g_vkCount; i++)
            RoundedBox(dc, g_vk[i].r, 12, RGB(30, 36, 54), RGB(40, 48, 70), 1);
        SelectObject(dc, fk);
        SetTextColor(dc, RGB(70, 80, 100));
        for (int i = 0; i < g_vkCount; i++) {
            wchar_t lb[2] = { (wchar_t)g_vk[i].ch, 0 };
            DrawTextW(dc, lb, -1, &g_vk[i].r, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        }
        SelectObject(dc, f1); DeleteObject(f1);
        SelectObject(dc, f2); DeleteObject(f2);
        SelectObject(dc, f3); DeleteObject(f3);
        SelectObject(dc, fk); DeleteObject(fk);
        SelectObject(dc, fb); DeleteObject(fb);
        return;
    }

    /* 密码显示框 */
    RoundedBox(dc, g_rcDisplay, 14, RGB(30, 38, 60), CLR_ACCENT, 2);
    SelectObject(dc, f3);
    RECT inner = g_rcDisplay; InflateRect(&inner, -14, -8);
    if (g_inputLen == 0) {
        SetTextColor(dc, RGB(90, 108, 136));
        SelectObject(dc, f2);
        DrawTextW(dc, L"屏幕键盘或物理键盘输入均可…", -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    } else {
        wchar_t mask[64];
        if (g_inputLen > 24) wsprintfW(mask, L"● ×%d（已输入 %d 位）", g_inputLen, g_inputLen);
        else {
            int i; for (i = 0; i < g_inputLen; i++) mask[i] = L'●';
            mask[i] = 0;
        }
        SetTextColor(dc, CLR_ACCENT);
        DrawTextW(dc, mask, -1, &inner, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    /* 退格键 */
    RoundedBox(dc, g_rcBack, 14, g_hoverBtn == 3 ? CLR_KEY_HOVER : CLR_KEY_FILL, CLR_KEY_EDGE, 1);
    SelectObject(dc, fb);
    SetTextColor(dc, g_hoverBtn == 3 ? CLR_ACCENT : CLR_TEXT);
    DrawTextW(dc, L"⌫", -1, &g_rcBack, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    /* 确认（主色实心）/ 取消（红色描边）按钮 */
    RoundedBox(dc, g_rcConfirm, 16, g_hoverBtn == 1 ? RGB(106, 210, 255) : CLR_ACCENT, RGB(140, 214, 255), 1);
    SelectObject(dc, fb);
    SetTextColor(dc, RGB(12, 22, 38));
    DrawTextW(dc, L"✔  确认解锁", -1, &g_rcConfirm, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    RoundedBox(dc, g_rcCancel, 16, g_hoverBtn == 2 ? RGB(60, 32, 40) : RGB(40, 28, 38), CLR_DANGER, 1);
    SetTextColor(dc, CLR_DANGER);
    DrawTextW(dc, L"⏏  取消并弹出U盘", -1, &g_rcCancel, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    /* 屏幕键盘 */
    SelectObject(dc, fk);
    for (int i = 0; i < g_vkCount; i++) {
        BOOL hov = (i == g_hoverKey);
        RoundedBox(dc, g_vk[i].r, 12, hov ? CLR_KEY_HOVER : CLR_KEY_FILL,
                   hov ? CLR_ACCENT : CLR_KEY_EDGE, hov ? 2 : 1);
        SetTextColor(dc, hov ? CLR_ACCENT : CLR_TEXT);
        wchar_t lb[2] = { (wchar_t)g_vk[i].ch, 0 };
        DrawTextW(dc, lb, -1, &g_vk[i].r, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    SelectObject(dc, f1); DeleteObject(f1);
    SelectObject(dc, f2); DeleteObject(f2);
    SelectObject(dc, f3); DeleteObject(f3);
    SelectObject(dc, fk); DeleteObject(fk);
    SelectObject(dc, fb); DeleteObject(fb);
}

static void ShowLockWindow(void);
static void ShowTrayWindow(void);
static ATOM RegOneClass(WNDPROC proc, const wchar_t *name, HBRUSH bg);

static void EnterStandby(void)
{
    if (g_hTrayWnd) return;
    ShowTrayWindow();
}

static void DoConfirm(HWND wnd)
{
    if (g_inputLen == 0) return;
    const WCHAR *err = ModeCheckInput(g_state.mode, g_input);
    if (err) { MessageBoxW(wnd, err, APP_NAME, MB_ICONWARNING); return; }
    WCHAR tmp[MAX_PWD + 1]; wcscpy(tmp, g_input);
    if (CheckPassword(tmp)) UnlockSuccess(wnd);
    else OnWrongPassword(wnd);
}

static void DoCancel(HWND wnd)
{
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

static LRESULT CALLBACK LockProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        InputClear();   /* v2.1.1.5：每次打开锁屏都清空输入，防止残留密码直接点确认通过 */
        SetTimer(wnd, 2, 500, NULL);
        SetFocus(wnd);
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wp) != WA_INACTIVE) SetFocus(wnd);   /* 激活时夺回焦点，物理键盘可用 */
        return 0;
    case WM_TIMER:
        if (wp == 2) {
            SetWindowPos(wnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            if (g_state.lockUntil && time(NULL) >= (time_t)g_state.lockUntil)
                g_state.lockUntil = 0, SaveState();
            InvalidateRect(wnd, NULL, FALSE);   /* 双缓冲下重画无闪烁 */
        }
        return 0;
    case WM_ERASEBKGND:
        return 1;   /* 背景在 WM_PAINT 内存位图中绘制，不单独擦除（防闪烁） */
    case WM_SIZE:
        BuildLockLayout(wnd);
        InvalidateRect(wnd, NULL, FALSE);
        return 0;
    case WM_PAINT: {
        /* 双缓冲：先在内存位图上画完整帧，再一次性贴到屏幕（根治闪烁） */
        PAINTSTRUCT ps;
        HDC wdc = BeginPaint(wnd, &ps);
        RECT rc; GetClientRect(wnd, &rc);
        HDC mem = CreateCompatibleDC(wdc);
        HBITMAP bm = CreateCompatibleBitmap(wdc, rc.right, rc.bottom);
        HBITMAP ob = (HBITMAP)SelectObject(mem, bm);
        PaintLock(wnd, mem, rc.right, rc.bottom);
        BitBlt(wdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, ob);
        DeleteObject(bm);
        DeleteDC(mem);
        EndPaint(wnd, &ps);
        return 0;
    }
    case WM_MOUSEMOVE: {
        int hit = HitKey(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        int newKey = hit >= 0 ? hit : -1;
        int newBtn = hit == -2 ? 3 : hit == -3 ? 1 : hit == -4 ? 2 : 0;
        if (newKey != g_hoverKey || newBtn != g_hoverBtn) {
            g_hoverKey = newKey; g_hoverBtn = newBtn;
            InvalidateRect(wnd, NULL, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        int hit = HitKey(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        SetFocus(wnd);
        time_t now = time(NULL);
        if (now < (time_t)g_state.lockUntil) return 0;
        if (hit >= 0)      InputAppend((wchar_t)g_vk[hit].ch);
        else if (hit == -2) InputBack();
        else if (hit == -3) DoConfirm(wnd);
        else if (hit == -4) DoCancel(wnd);
        return 0;
    }
    case WM_CHAR: {
        /* 物理键盘输入（密钥模式支持任意可见字符） */
        time_t now = time(NULL);
        if (now < (time_t)g_state.lockUntil) return 0;
        wchar_t c = (wchar_t)wp;
        if (c == 8) { InputBack(); return 0; }
        if (c == 13) { DoConfirm(wnd); return 0; }
        if (c < 0x20) return 0;
        InputAppend(c);   /* InputAppend 内部已做模式过滤 */
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_CONFIRM) DoConfirm(wnd);
        else if (LOWORD(wp) == IDC_BACKSPACE) InputBack();
        return 0;
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
    nid.hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(100));
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
static wchar_t g_verifyBuf[MAX_PWD + 1];   /* v2.1.1：记录本次输入的密码文本 */

static LRESULT CALLBACK VerifyProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT fn = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        CreateWindowW(L"STATIC", L"请输入密码：", WS_CHILD|WS_VISIBLE, 20, 20, 340, 24, wnd, NULL, g_hInst, NULL);
        g_hVerifyEdit = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            20, 52, 340, 30, wnd, (HMENU)(INT_PTR)101, g_hInst, NULL);
        HWND ok = CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            100, 100, 80, 32, wnd, (HMENU)(INT_PTR)102, g_hInst, NULL);
        HWND no = CreateWindowW(L"BUTTON", L"取消", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            200, 100, 80, 32, wnd, (HMENU)(INT_PTR)103, g_hInst, NULL);
        SendMessageW(g_hVerifyEdit, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(ok, WM_SETFONT, (WPARAM)fn, TRUE);
        SendMessageW(no, WM_SETFONT, (WPARAM)fn, TRUE);
        DeleteObject(fn);
        SetFocus(g_hVerifyEdit);
        return 0;
    }
    case WM_ERASEBKGND: return ModernErase(wnd, (HDC)wp);
    case WM_CTLCOLORSTATIC: return ModernStatic((HDC)wp);
    case WM_CTLCOLOREDIT:   return ModernEdit((HDC)wp);
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lp;
        if (dis->CtlID == 102) return ModernBtnDraw(dis, CLR_ACCENT, RGB(140,214,255), RGB(12,22,38));
        if (dis->CtlID == 103) return ModernBtnDraw(dis, RGB(40,48,72), CLR_KEY_EDGE, CLR_TEXT);
        return FALSE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == 102) {
            wchar_t buf[MAX_PWD + 1];
            GetWindowTextW(g_hVerifyEdit, buf, MAX_PWD + 1);
            wcscpy(g_verifyBuf, buf);
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
    int newMode = DetectMode(nw1);   /* v2.1.1：模式自动跟随 */
    WCHAR hex[65];
    if (Sha256Hex(nw1, hex) && SavePasswordHash(hex)) {
        g_state.fails = 0; g_state.lockUntil = 0;
        g_state.mode = newMode;
        SaveState();
        wchar_t msg[160];
        wsprintfW(msg, L"锁屏密码已重置！\n解锁模式：%s", ModeName(newMode));
        MessageBoxW(wnd, msg, APP_NAME, MB_OK | MB_ICONINFORMATION);
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
        HWND bv = CreateWindowW(L"BUTTON", L"验证", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
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
        CreateWindowW(L"BUTTON", L"重置密码", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            105, 105, 120, 30, g_hSupPanel, (HMENU)(INT_PTR)205, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 忘记密码重置期限 ──", WS_CHILD|WS_VISIBLE, 12, 145, 220, 22, g_hSupPanel, NULL, g_hInst, NULL);
        g_hSupForget = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, 12, 170, 200, 120, g_hSupPanel, (HMENU)(INT_PTR)206, g_hInst, NULL);
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"关闭");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"24 小时后自动重置");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"30 天后自动重置");
        SendMessageW(g_hSupForget, CB_ADDSTRING, 0, (LPARAM)L"365 天后自动重置");
        CreateWindowW(L"BUTTON", L"保存期限", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
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
    case WM_ERASEBKGND: return ModernErase(wnd, (HDC)wp);
    case WM_CTLCOLORSTATIC: return ModernStatic((HDC)wp);
    case WM_CTLCOLOREDIT:   return ModernEdit((HDC)wp);
    case WM_CTLCOLORBTN:    return ModernStatic((HDC)wp);
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lp;
        if (dis->CtlID == 202 || dis->CtlID == 205 || dis->CtlID == 207)
            return ModernBtnDraw(dis, CLR_ACCENT, RGB(140,214,255), RGB(12,22,38));
        return FALSE;
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
                if (!Sha256Hex(rec, nh) || !WriteHexFile(g_recFile, nh)) {
                    MessageBoxW(wnd, L"写入失败", APP_NAME, MB_ICONERROR);
                    return 0;
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
    RegOneClass(SuperProc, L"USBsafelySuper", NULL);
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
    /* v2.1.1：模式随新密码自动切换，不再需要手动点"应用模式"，杜绝不匹配锁死 */
    int newMode = DetectMode(nw1);
    int oldMode = g_state.mode;
    WCHAR hex[65];
    if (Sha256Hex(nw1, hex) && SavePasswordHash(hex)) {
        g_state.mode = newMode;
        SaveState();
        wchar_t msg[192];
        if (newMode != oldMode)
            wsprintfW(msg, L"密码修改成功！\n解锁模式已自动切换为：%s", ModeName(newMode));
        else
            wsprintfW(msg, L"密码修改成功！（解锁模式：%s）", ModeName(newMode));
        MessageBoxW(wnd, msg, APP_NAME, MB_OK | MB_ICONINFORMATION);
        SetWindowTextW(g_hOld, L""); SetWindowTextW(g_hNew, L""); SetWindowTextW(g_hNew2, L"");
    } else
        MessageBoxW(wnd, L"写入密码文件失败（已自动校验，文件不会被损坏）", APP_NAME, MB_ICONERROR);
}

static void DoSaveMode(HWND wnd)
{
    int sel = (int)SendMessageW(g_hModeCombo, CB_GETCURSEL, 0, 0);
    if (sel < 0 || sel > 4) return;
    if (sel == g_state.mode) return;
    /* v2.1.1：切换模式需验证当前密码，且当前密码必须符合新模式，
       防止"数字模式 + 字母密码"这种把自己锁死的组合 */
    if (!VerifyPasswordDialog(wnd, L"切换解锁模式 · 请输入当前密码确认"))
        return;
    if (sel != 0) {
        BOOL ok = TRUE;
        for (const wchar_t *p = g_verifyBuf; *p; p++)
            if (!ModeAllowChar(sel, *p)) { ok = FALSE; break; }
        const WCHAR *err = ok ? ModeCheckInput(sel, g_verifyBuf) : NULL;
        if (!ok || err) {
            MessageBoxW(wnd,
                L"当前密码不符合所选模式，切换后你将无法解锁！\n\n"
                L"请先修改一个符合该模式的密码（修改密码时模式会自动跟随），\n"
                L"或者选择与当前密码匹配的模式。",
                APP_NAME, MB_OK | MB_ICONWARNING);
            SendMessageW(g_hModeCombo, CB_SETCURSEL, g_state.mode, 0);
            return;
        }
    }
    g_state.mode = sel;
    SaveState();
    MessageBoxW(wnd, L"解锁模式已更新（已验证当前密码兼容，立即生效）", APP_NAME, MB_OK | MB_ICONINFORMATION);
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
        HWND sm = CreateWindowW(L"BUTTON", L"应用模式", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
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
        HWND chg = CreateWindowW(L"BUTTON", L"修改密码", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            125, 232, 160, 34, wnd, (HMENU)(INT_PTR)IDC_BTNCHG, g_hInst, NULL);
        CreateWindowW(L"STATIC", L"── 关于程序 ──", WS_CHILD|WS_VISIBLE, 30, 280, 340, 26, wnd, NULL, g_hInst, NULL);
        g_hVerLabel = CreateWindowW(L"BUTTON", L"版本 " APP_VER L"（连点5下开启超级模式）",
            WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, 30, 310, 355, 34, wnd, (HMENU)(INT_PTR)IDC_VERLBL, g_hInst, NULL);
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
    case WM_ERASEBKGND: return ModernErase(wnd, (HDC)wp);
    case WM_CTLCOLORSTATIC: return ModernStatic((HDC)wp);
    case WM_CTLCOLOREDIT:   return ModernEdit((HDC)wp);
    case WM_CTLCOLORBTN:    return ModernStatic((HDC)wp);
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lp;
        if (dis->CtlID == IDC_BTNCHG || dis->CtlID == IDC_BTNSAVE)
            return ModernBtnDraw(dis, CLR_ACCENT, RGB(140,214,255), RGB(12,22,38));
        if (dis->CtlID == IDC_VERLBL)
            return ModernBtnDraw(dis, RGB(40,48,72), CLR_KEY_EDGE, CLR_ACCENT);
        return FALSE;
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
    wc.hbrBackground = bg;   /* NULL = 由窗口过程自绘渐变背景（v2.1.0） */
    wc.hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(100));
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
    RegOneClass(TrayProc, L"USBsafelyTray", NULL);
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

    RegOneClass(SetupProc,  L"USBsafelySetup",  NULL);
    RegOneClass(VerifyProc, L"USBsafelyVerify", NULL);

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
