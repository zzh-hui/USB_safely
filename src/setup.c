/* =====================================================================
 * USB_safely-Setup — 安装 / 卸载 二合一程序 v2.0.0
 * ---------------------------------------------------------------------
 * 安装模式（未安装时自动进入）：
 *   1. 选择安装目录（默认 C:\USBsafely，可为硬盘目录做测试，也可为 U 盘）
 *   2. 设置启动密码（首次强制 4 位数字，之后可在程序内修改）
 *   3. 释放内嵌的 USBsafely.exe + 辅助 bat + autorun.inf
 *   4. 写入注册表卸载项（控制面板可看到，可一键卸载）
 * 卸载模式（已安装时自动进入，或 /uninstall 参数）：
 *   1. 验证启动密码（卸载保护）
 *   2. 删除全部文件 + 注册表项，零残留（卸载器自删除）
 * ===================================================================== */
#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APP_NAME  L"USB_safely"
#define APP_VER   L"V2.1.0"
#define REG_KEY   L"Software\\USBsafely"
#define REG_UNINS L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\USBsafely"

static HINSTANCE g_hInst;
static WCHAR  g_selfPath[MAX_PATH];
static WCHAR  g_install[MAX_PATH] = L"C:\\USBsafely";
static int    g_installed = 0;          /* 1=已安装（卸载模式） */

/* 控件 */
static HWND g_hPathEdit, g_hPin1, g_hPin2, g_hLog;
static HWND g_hUnPin;

/* ---------------- SHA256 ---------------- */
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

static void Log(HWND wnd, const WCHAR *text)
{
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)text);
    UpdateWindow(g_hLog);
}

/* 释放内嵌的 USBsafely.exe（资源 ID 1 RCDATA） */
static BOOL DropMainExe(const WCHAR *dest)
{
    HRSRC hr = FindResourceW(NULL, MAKEINTRESOURCEW(1), RT_RCDATA);
    if (!hr) return FALSE;
    HGLOBAL hg = LoadResource(NULL, hr);
    if (!hg) return FALSE;
    LPVOID data = LockResource(hg);
    DWORD size = SizeofResource(NULL, hr);
    if (!data || !size) return FALSE;
    FILE *f = _wfopen(dest, L"wb");
    if (!f) return FALSE;
    BOOL ok = fwrite(data, 1, size, f) == size;
    fclose(f);
    return ok;
}

static void WriteTextFile(const WCHAR *path, const char *utf8)
{
    /* UTF-8 无 BOM（cmd 批处理带 BOM 会导致首行报错），bat 内已 chcp 65001 */
    FILE *f = _wfopen(path, L"wb");
    if (!f) return;
    fwrite(utf8, 1, strlen(utf8), f);
    fclose(f);
}

static void WriteDirFile(const WCHAR *dir, const WCHAR *name, const char *utf8)
{
    wchar_t path[MAX_PATH];
    wsprintfW(path, L"%s\\%s", dir, name);
    WriteTextFile(path, utf8);
}

static void SetRegStr(HKEY root, const WCHAR *sub, const WCHAR *name, const WCHAR *val)
{
    HKEY k;
    if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)val, (DWORD)((wcslen(val) + 1) * sizeof(WCHAR)));
        RegCloseKey(k);
    }
}

static BOOL GetRegStr(const WCHAR *sub, const WCHAR *name, WCHAR *out, DWORD cch)
{
    HKEY k;
    DWORD type = 0, sz = cch * sizeof(WCHAR);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return FALSE;
    BOOL ok = RegQueryValueExW(k, name, NULL, &type, (BYTE *)out, &sz) == ERROR_SUCCESS && type == REG_SZ;
    RegCloseKey(k);
    return ok;
}

/* ---------------- v2.1.0 现代化 UI ---------------- */
static void FillVGrad(HDC dc, RECT rc, COLORREF c1, COLORREF c2)
{
    TRIVERTEX tv[2] = {
        { rc.left,  rc.top,    (USHORT)(GetRValue(c1) << 8), (USHORT)(GetGValue(c1) << 8), (USHORT)(GetBValue(c1) << 8), 0 },
        { rc.right, rc.bottom, (USHORT)(GetRValue(c2) << 8), (USHORT)(GetGValue(c2) << 8), (USHORT)(GetBValue(c2) << 8), 0 }
    };
    GRADIENT_RECT gr = { 0, 1 };
    GradientFill(dc, tv, 2, &gr, 1, GRADIENT_FILL_RECT_V);
}
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
#define CLR_BG_TOP     RGB(26, 32, 52)
#define CLR_BG_BOTTOM  RGB(44, 38, 68)
#define CLR_ACCENT     RGB(76, 194, 255)
#define CLR_TEXT       RGB(232, 240, 252)
static HBRUSH g_hEditBrush = NULL;
static LRESULT ModernErase(HWND wnd, HDC dc)
{
    RECT rc; GetClientRect(wnd, &rc);
    FillVGrad(dc, rc, CLR_BG_TOP, CLR_BG_BOTTOM);
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
    HFONT f = CreateFontW(17, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    HFONT of = (HFONT)SelectObject(dis->hDC, f);
    WCHAR txt[96]; GetWindowTextW(dis->hwndItem, txt, 96);
    DrawTextW(dis->hDC, txt, -1, &dis->rcItem, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(dis->hDC, of);
    DeleteObject(f);
    return TRUE;
}

/* ---------------- 安装 ---------------- */
static void DoInstall(HWND wnd)
{
    wchar_t pin1[8], pin2[8];
    GetWindowTextW(g_hPin1, pin1, 8);
    GetWindowTextW(g_hPin2, pin2, 8);
    GetWindowTextW(g_hPathEdit, g_install, MAX_PATH);

    /* 校验 */
    if (wcslen(pin1) != 4) { MessageBoxW(wnd, L"首次启动密码必须是 4 位数字！", APP_NAME, MB_ICONWARNING); return; }
    for (int i = 0; i < 4; i++) if (pin1[i] < L'0' || pin1[i] > L'9') { MessageBoxW(wnd, L"首次启动密码必须是 4 位数字！", APP_NAME, MB_ICONWARNING); return; }
    if (wcscmp(pin1, pin2) != 0) { MessageBoxW(wnd, L"两次输入的密码不一致！", APP_NAME, MB_ICONWARNING); return; }

    SetWindowTextW(g_hLog, L"");
    Log(wnd, L"[1/6] 创建安装目录...\r\n");
    if (!CreateDirectoryW(g_install, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        MessageBoxW(wnd, L"创建目录失败（路径无效或无权限）", APP_NAME, MB_ICONERROR); return;
    }

    Log(wnd, L"[2/6] 释放主程序 USBsafely.exe...\r\n");
    wchar_t mainExe[MAX_PATH]; wsprintfW(mainExe, L"%s\\USBsafely.exe", g_install);
    if (!DropMainExe(mainExe)) {
        MessageBoxW(wnd, L"释放主程序失败！", APP_NAME, MB_ICONERROR); return;
    }

    Log(wnd, L"[3/6] 写入辅助脚本...\r\n");
    WriteDirFile(g_install, L"run.bat",
        "@echo off\r\nchcp 65001 >nul\r\nstart \"\" \"%~dp0USBsafely.exe\"\r\n");
    WriteDirFile(g_install, L"setup.bat",
        "@echo off\r\nchcp 65001 >nul\r\nstart \"\" \"%~dp0USBsafely.exe\" setup\r\n");
    WriteDirFile(g_install, L"intro.bat",
        "@echo off\r\nchcp 65001 >nul\r\necho USB_safely v2.0 - run.bat=\xe5\x90\xaf\xe5\x8a\xa8\xe9\x94\x81\xe5\xae\x9a  setup.bat=\xe8\xae\xbe\xe7\xbd\xae\r\necho \xe5\x8d\xb8\xe8\xbd\xbd\xef\xbc\x9a\xe5\x86\x8d\xe6\xac\xa1\xe8\xbf\x90\xe8\xa1\x8c USBsafely-Setup.exe\r\npause\r\n");
    WriteDirFile(g_install, L"autorun.inf",
        "[autorun]\r\nopen=USBsafely.exe\r\naction=Start USB Lock\r\nlabel=USB_safely\r\nicon=USBsafely.exe\r\n");
    /* 卸载器（复制自身到安装目录） */
    wchar_t setupDst[MAX_PATH]; wsprintfW(setupDst, L"%s\\USBsafely-Setup.exe", g_install);
    CopyFileW(g_selfPath, setupDst, FALSE);

    Log(wnd, L"[4/6] 写入密码文件（SHA256）...\r\n");
    wchar_t pwDir[MAX_PATH]; wsprintfW(pwDir, L"%s\\password", g_install);
    CreateDirectoryW(pwDir, NULL);
    WCHAR hex[65];
    if (!Sha256Hex(pin1, hex)) { MessageBoxW(wnd, L"密码加密失败", APP_NAME, MB_ICONERROR); return; }
    wchar_t pwFile[MAX_PATH]; wsprintfW(pwFile, L"%s\\pw.sf", pwDir);
    {
        /* 哈希是纯 ASCII，按字节写，避免宽流 %s 的未定义行为 */
        FILE *f = _wfopen(pwFile, L"wb");
        if (!f) { MessageBoxW(wnd, L"写入密码文件失败", APP_NAME, MB_ICONERROR); return; }
        char b[66];
        for (int i = 0; i < 64; i++) b[i] = (char)hex[i];
        b[64] = '\n'; b[65] = 0;
        if (fwrite(b, 1, 65, f) != 65) {
            fclose(f);
            MessageBoxW(wnd, L"写入密码文件失败", APP_NAME, MB_ICONERROR); return;
        }
        fclose(f);
    }
    wchar_t stFile[MAX_PATH]; wsprintfW(stFile, L"%s\\state.sf", pwDir);
    FILE *sf = _wfopen(stFile, L"w");
    if (sf) { fwprintf(sf, L"mode=1\nfails=0\nlockUntil=0\nforget=0\nformatOn=0\nuninstProt=1\n"); fclose(sf); }

    Log(wnd, L"[5/6] 写入注册表（卸载项）...\r\n");
    SetRegStr(HKEY_CURRENT_USER, REG_KEY, L"InstallPath", g_install);
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"DisplayName", APP_NAME L" U盘锁");
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"DisplayVersion", L"2.1.0");
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"Publisher", L"APPLE_INT · Geek-Hub");
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"DisplayIcon", mainExe);
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"InstallLocation", g_install);
    wchar_t unins[MAX_PATH * 2];
    wsprintfW(unins, L"\"%s\\USBsafely-Setup.exe\" /uninstall", g_install);
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"UninstallString", unins);
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"NoModify", L"1");
    SetRegStr(HKEY_CURRENT_USER, REG_UNINS, L"NoRepair", L"1");

    Log(wnd, L"[6/6] 完成！\r\n\r\n安装成功！\r\n启动锁定：双击 run.bat（或 USBsafely.exe）\r\n修改设置：双击 setup.bat\r\n卸载：控制面板 → 应用，或再次运行本程序\r\n\r\n启动密码为你的 4 位数字。");
    MessageBoxW(wnd, L"✔ 安装成功！\n\n锁定测试请双击安装目录里的 run.bat\n（硬盘安装时用于测试，正式使用请安装进 U 盘根目录）",
        APP_NAME, MB_OK | MB_ICONINFORMATION);
}

/* ---------------- 卸载 ---------------- */
static void DoUninstall(HWND wnd)
{
    wchar_t pin[8];
    GetWindowTextW(g_hUnPin, pin, 8);

    /* 验证启动密码（卸载保护）：密码文件存在则必须通过验证 */
    WCHAR want[65], hex[65];
    wchar_t pwFile[MAX_PATH];
    wsprintfW(pwFile, L"%s\\password\\pw.sf", g_install);
    FILE *f = _wfopen(pwFile, L"r");
    if (f) {
        wchar_t line[256]; BOOL have = FALSE;
        if (fgetws(line, 256, f)) {
            wchar_t *p = line; int n = 0;
            while (*p == L' ') p++;
            while (p[n] && p[n] != L'\r' && p[n] != L'\n' && n < 64) n++;
            if (n == 64) { wcsncpy(want, p, 64); want[64] = 0; have = TRUE; }
        }
        fclose(f);
        if (!have) {
            /* 密码文件损坏无法验证 → 明确提示，需二次确认后才能继续 */
            if (MessageBoxW(wnd,
                    L"密码文件已损坏，无法验证启动密码。\n\n继续卸载将不做密码校验（可能是程序被破坏），确定继续吗？",
                    APP_NAME" 卸载", MB_YESNO | MB_ICONWARNING) != IDYES) return;
        } else {
            if (wcslen(pin) < 1) { MessageBoxW(wnd, L"请输入启动密码以确认卸载", APP_NAME, MB_ICONWARNING); return; }
            Sha256Hex(pin, hex);
            if (_wcsicmp(hex, want) != 0) {
                MessageBoxW(wnd, L"密码错误！卸载已取消。", APP_NAME, MB_ICONERROR);
                return;
            }
        }
    } else {
        if (MessageBoxW(wnd,
                L"未找到密码文件（卸载保护失效）。\n\n这可能意味着密码被非法删除，确定继续卸载吗？",
                APP_NAME" 卸载", MB_YESNO | MB_ICONWARNING) != IDYES) return;
    }

    if (MessageBoxW(wnd,
            L"确定要卸载 USB_safely 吗？\n\n将删除：程序文件、密码文件、注册表项（零残留）",
            APP_NAME" 卸载", MB_YESNO | MB_ICONQUESTION) != IDYES) return;
    if (MessageBoxW(wnd,
            L"再次确认：真的要卸载吗？\n（密码文件也会一并删除，卸载后需重新安装并设置密码）",
            APP_NAME" 卸载", MB_YESNO | MB_ICONWARNING) != IDYES) return;

    Log(wnd, L"[1/4] 结束后台主程序进程...\r\n");
    /* 密码验证已通过 → 强制结束主程序，防止文件删掉后主程序卡在后台（v2.0.2） */
    ShellExecuteW(wnd, L"open", L"taskkill.exe", L"/IM USBsafely.exe /F", NULL, SW_HIDE);
    Sleep(1000);

    Log(wnd, L"[2/4] 删除注册表项...\r\n");
    RegDeleteTreeW(HKEY_CURRENT_USER, REG_KEY);
    RegDeleteTreeW(HKEY_CURRENT_USER, REG_UNINS);

    Log(wnd, L"[3/4] 删除程序文件...\r\n");
    /* 先删数据与主程序（保留卸载器自身最后删） */
    wchar_t tmp[MAX_PATH];
    wsprintfW(tmp, L"%s\\password", g_install);
    wchar_t delCmd[MAX_PATH * 4];
    /* 延迟自删除：卸载器退出后由 cmd 删除整个目录 */
    wsprintfW(delCmd,
        L"/c ping -n 2 127.0.0.1 > nul & rd /s /q \"%s\"", g_install);
    /* 手动逐个删可见文件，让日志好看，目录残余交给 rd */
    wsprintfW(tmp, L"%s\\USBsafely.exe", g_install);   DeleteFileW(tmp);
    wsprintfW(tmp, L"%s\\run.bat", g_install);         DeleteFileW(tmp);
    wsprintfW(tmp, L"%s\\setup.bat", g_install);       DeleteFileW(tmp);
    wsprintfW(tmp, L"%s\\intro.bat", g_install);       DeleteFileW(tmp);
    wsprintfW(tmp, L"%s\\autorun.inf", g_install);     DeleteFileW(tmp);
    wsprintfW(tmp, L"%s\\USBsafely-Setup.exe", g_install);

    Log(wnd, L"[4/4] 清理完成，卸载器自删除...\r\n");
    MessageBoxW(wnd, L"✔ 卸载完成，所有文件与注册表已清理干净。", APP_NAME, MB_OK | MB_ICONINFORMATION);
    ShellExecuteW(wnd, L"open", L"cmd.exe", delCmd, NULL, SW_HIDE);
    ExitProcess(0);
}

/* ---------------- 界面 ---------------- */
#define IDC_PATH     1001
#define IDC_BROWSE   1002
#define IDC_PIN1     1003
#define IDC_PIN2     1004
#define IDC_GO       1005
#define IDC_UNPIN    1006

static LRESULT CALLBACK SetupWndProc(HWND wnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HFONT f  = CreateFontW(18, 0, 0, 0, FW_BOLD,   0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        HFONT fn = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");
        HFONT fb = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET, 0,0,CLEARTYPE_QUALITY,0, L"Segoe UI");

        if (!g_installed) {
            CreateWindowW(L"STATIC", L"USB_safely U盘锁 安装程序 " APP_VER, WS_CHILD|WS_VISIBLE, 20, 15, 420, 28, wnd, NULL, g_hInst, NULL);
            CreateWindowW(L"STATIC", L"安装目录（可填 U 盘盘符根目录，或硬盘目录用于测试）：", WS_CHILD|WS_VISIBLE, 20, 55, 420, 22, wnd, NULL, g_hInst, NULL);
            g_hPathEdit = CreateWindowW(L"EDIT", g_install, WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                20, 80, 330, 28, wnd, (HMENU)(INT_PTR)IDC_PATH, g_hInst, NULL);
            CreateWindowW(L"BUTTON", L"…", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                358, 79, 60, 30, wnd, (HMENU)(INT_PTR)IDC_BROWSE, g_hInst, NULL);
            CreateWindowW(L"STATIC", L"启动密码（首次必须 4 位数字，之后可在程序内修改）：", WS_CHILD|WS_VISIBLE, 20, 122, 420, 22, wnd, NULL, g_hInst, NULL);
            CreateWindowW(L"STATIC", L"密码：", WS_CHILD|WS_VISIBLE, 20, 155, 60, 22, wnd, NULL, g_hInst, NULL);
            g_hPin1 = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_PASSWORD,
                85, 152, 120, 28, wnd, (HMENU)(INT_PTR)IDC_PIN1, g_hInst, NULL);
            CreateWindowW(L"STATIC", L"确认：", WS_CHILD|WS_VISIBLE, 225, 155, 60, 22, wnd, NULL, g_hInst, NULL);
            g_hPin2 = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER|ES_PASSWORD,
                290, 152, 120, 28, wnd, (HMENU)(INT_PTR)IDC_PIN2, g_hInst, NULL);
            HWND go = CreateWindowW(L"BUTTON", L"安  装", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                20, 200, 180, 40, wnd, (HMENU)(INT_PTR)IDC_GO, g_hInst, NULL);
            g_hLog = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
                20, 255, 420, 130, wnd, NULL, g_hInst, NULL);
            SendMessageW(go, WM_SETFONT, (WPARAM)f, TRUE);
            SendMessageW(g_hPathEdit, WM_SETFONT, (WPARAM)fn, TRUE);
            SendMessageW(g_hPin1, WM_SETFONT, (WPARAM)fn, TRUE);
            SendMessageW(g_hPin2, WM_SETFONT, (WPARAM)fn, TRUE);
            SendMessageW(g_hLog, WM_SETFONT, (WPARAM)fb, TRUE);
        } else {
            CreateWindowW(L"STATIC", L"USB_safely U盘锁 卸载程序 " APP_VER, WS_CHILD|WS_VISIBLE, 20, 15, 420, 28, wnd, NULL, g_hInst, NULL);
            wchar_t loc[MAX_PATH + 64];
            wsprintfW(loc, L"安装位置：%s", g_install);
            CreateWindowW(L"STATIC", loc, WS_CHILD|WS_VISIBLE, 20, 55, 420, 22, wnd, NULL, g_hInst, NULL);
            CreateWindowW(L"STATIC", L"卸载保护：请输入启动密码确认：", WS_CHILD|WS_VISIBLE, 20, 90, 420, 22, wnd, NULL, g_hInst, NULL);
            g_hUnPin = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
                20, 118, 200, 28, wnd, (HMENU)(INT_PTR)IDC_UNPIN, g_hInst, NULL);
            HWND go = CreateWindowW(L"BUTTON", L"卸  载", WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
                20, 160, 180, 40, wnd, (HMENU)(INT_PTR)IDC_GO, g_hInst, NULL);
            g_hLog = CreateWindowW(L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,
                20, 215, 420, 110, wnd, NULL, g_hInst, NULL);
            SendMessageW(go, WM_SETFONT, (WPARAM)f, TRUE);
            SendMessageW(g_hUnPin, WM_SETFONT, (WPARAM)fn, TRUE);
            SendMessageW(g_hLog, WM_SETFONT, (WPARAM)fb, TRUE);
        }
        /* 标题字体 */
        HWND hTitle = GetWindow(wnd, GW_CHILD);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)f, TRUE);
        DeleteObject(f); DeleteObject(fn); DeleteObject(fb);
        return 0;
    }
    case WM_ERASEBKGND: return ModernErase(wnd, (HDC)wp);
    case WM_CTLCOLORSTATIC: return ModernStatic((HDC)wp);
    case WM_CTLCOLOREDIT:   return ModernEdit((HDC)wp);
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lp;
        if (dis->CtlID == IDC_GO)      return ModernBtnDraw(dis, CLR_ACCENT, RGB(140,214,255), RGB(12,22,38));
        if (dis->CtlID == IDC_BROWSE)  return ModernBtnDraw(dis, RGB(40,48,72), RGB(66,86,124), CLR_TEXT);
        return FALSE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp), ev = HIWORD(wp);
        if (id == IDC_BROWSE && ev == BN_CLICKED) {
            wchar_t buf[MAX_PATH];
            BROWSEINFOW bi = { 0 };
            bi.hwndOwner = wnd;
            bi.lpszTitle = L"选择安装目录（可为 U 盘根目录或硬盘目录）";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, buf)) SetWindowTextW(g_hPathEdit, buf);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_GO && ev == BN_CLICKED) {
            if (g_installed) DoUninstall(wnd);
            else DoInstall(wnd);
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(wnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE prev, LPWSTR cmd, int show)
{
    (void)prev; (void)show;
    g_hInst = hInst;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    GetModuleFileNameW(NULL, g_selfPath, MAX_PATH);

    /* 已安装检测：注册表有 InstallPath → 卸载模式 */
    if ((cmd && wcsstr(cmd, L"/uninstall")) ||
        GetRegStr(REG_KEY, L"InstallPath", g_install, MAX_PATH)) {
        g_installed = 1;
        if (!GetRegStr(REG_KEY, L"InstallPath", g_install, MAX_PATH)) {
            MessageBoxW(NULL, L"未找到安装信息（可能已卸载）。", APP_NAME, MB_ICONWARNING);
            return 1;
        }
    }

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = SetupWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(100));
    wc.lpszClassName = L"USBsafelySetupWnd";
    RegisterClassW(&wc);

    HWND w = CreateWindowW(L"USBsafelySetupWnd",
        g_installed ? L"USB_safely 卸载" : L"USB_safely 安装",
        (WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX)) | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 475, 440, NULL, NULL, hInst, NULL);
    (void)w;

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    CoUninitialize();
    return 0;
}
