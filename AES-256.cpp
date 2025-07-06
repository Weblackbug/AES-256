/////////////////////////////////////////////////////////////////////////////////
//      AES-256.cpp : Encriptador y Desencriptador de Archivos con AES-256     //
//                              AES-256 1.0                                    //
//           weblackbug (c) 2025 By Sergi .C Engineer softaware                //
//                             - Julio dia 6 -                                 //
/////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <commdlg.h>
#include <sstream>
#include "framework.h"
#include "AES-256.h"

#include "cryptopp890/aes.h"
#include "cryptopp890/modes.h"
#include "cryptopp890/filters.h"
#include "cryptopp890/sha.h"
#include "cryptopp890/secblock.h"
#include "cryptopp890/osrng.h"
#include "cryptopp890/base64.h"

#include <codecvt>
#include <locale>

#define MAX_LOADSTRING 100

#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#endif
#ifndef GET_Y_LPARAM
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];
std::wstring g_contenidoArchivo;
bool g_dragScroll = false;
POINT g_lastMousePos = { 0, 0 };
unsigned char* g_pBufferArchivo = nullptr;
size_t g_tamBufferArchivo = 0;
std::wstring g_nombreFichero;

ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);
void DerivarClaveSHA256(const std::wstring& password, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

// Detecta si el buffer corresponde a un archivo de texto legible
bool EsArchivoTexto(const std::vector<unsigned char>& buffer) {
    for (size_t i = 0; i < buffer.size() && i < 1024; ++i) {
        unsigned char c = buffer[i];
        if ((c < 32 && c != 9 && c != 10 && c != 13) || c == 0x7F) {
            return false;
        }
    }
    return true;
}

// Carga un archivo, detecta si es texto o binario y ajusta el buffer y la visualización
bool AbrirFichero(HWND hWnd)
{
    if (g_pBufferArchivo) {
        delete[] g_pBufferArchivo;
        g_pBufferArchivo = nullptr;
        g_tamBufferArchivo = 0;
    }
    OPENFILENAME ofn = { 0 };
    wchar_t szFile[MAX_PATH] = { 0 };

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Todos los archivos\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE)
    {
        g_nombreFichero = szFile;

        // Lee el archivo como binario para detección y cifrado
        std::ifstream file(szFile, std::ios::binary);
        if (!file)
            return false;
        std::vector<unsigned char> binContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        g_tamBufferArchivo = binContent.size();
        if (g_tamBufferArchivo == 0)
            return false;
        g_pBufferArchivo = new unsigned char[g_tamBufferArchivo];
        memcpy(g_pBufferArchivo, binContent.data(), g_tamBufferArchivo);

        bool esTexto = EsArchivoTexto(binContent);

        g_contenidoArchivo.clear();
        if (esTexto) {
            std::wifstream wfile(szFile);
            if (!wfile)
                return false;
            // Para archivos UTF-8, descomentar la siguiente línea:
            // wfile.imbue(std::locale(wfile.getloc(), new std::codecvt_utf8<wchar_t>()));
            std::wstring linea;
            while (std::getline(wfile, linea)) {
                g_contenidoArchivo += linea + L"\n";
            }
            wfile.close();
        }
        else {
            wchar_t hex[4];
            int col = 0;
            for (size_t i = 0; i < binContent.size(); ++i) {
                swprintf(hex, 4, L"%02X ", binContent[i]);
                g_contenidoArchivo += hex;
                if (++col == 16) {
                    g_contenidoArchivo += L"\n";
                    col = 0;
                }
            }
        }



        // Ajuste de scroll vertical y horizontal según el contenido cargado
        HDC hdc = GetDC(hWnd);
        TEXTMETRIC tm;
        GetTextMetrics(hdc, &tm);
        int lineHeight = tm.tmHeight;
        ReleaseDC(hWnd, hdc);

        int numLineas = 1;
        int maxLen = 0, currLen = 0;
        for (wchar_t c : g_contenidoArchivo) {
            if (c == L'\n') { ++numLineas; if (currLen > maxLen) maxLen = currLen; currLen = 0; }
            else ++currLen;
        }
        if (currLen > maxLen) maxLen = currLen;

        RECT rect;
        GetClientRect(hWnd, &rect);

        SCROLLINFO si = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE, 0, numLineas * lineHeight, (UINT)(rect.bottom - rect.top), 0, 0 };
        SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

        si.nMin = 0;
        si.nMax = maxLen * tm.tmAveCharWidth;
        si.nPage = rect.right - rect.left;
        SetScrollInfo(hWnd, SB_HORZ, &si, TRUE);

        return true;
    }
    return false;
}
bool GuardarFichero(HWND hWnd)
{
    if (!g_pBufferArchivo || g_tamBufferArchivo == 0) {
        MessageBox(hWnd, L"No hay datos en memoria para guardar.", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    OPENFILENAME ofn = { 0 };
    wchar_t szFile[MAX_PATH] = { 0 };

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Todos los archivos\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileName(&ofn) != TRUE) {
        // El usuario canceló o hubo error
        DWORD err = CommDlgExtendedError();
        if (err != 0) {
            MessageBox(hWnd, L"Error al mostrar el diálogo de guardado.", L"Error", MB_OK | MB_ICONERROR);
        }
        return false;
    }

    std::ofstream file(szFile, std::ios::binary);
    if (!file) {
        MessageBox(hWnd, L"No se pudo abrir el archivo para guardar.", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    file.write(reinterpret_cast<const char*>(g_pBufferArchivo), g_tamBufferArchivo);
    if (!file) {
        MessageBox(hWnd, L"Error al escribir en el archivo.", L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    file.close();
    MessageBox(hWnd, L"Archivo guardado correctamente.", L"Éxito", MB_OK | MB_ICONINFORMATION);
    return true;
}
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    setlocale(LC_ALL, "Spanish");

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_AES256, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow))
        return FALSE;

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_AES256));
    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_CANDADO));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_AES256);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_CANDADO));
    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance;
    HWND hWnd = CreateWindowW(
        szWindowClass, szTitle,
        WS_OVERLAPPEDWINDOW | WS_HSCROLL | WS_VSCROLL,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0,
        nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
        return FALSE;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

// Procedimiento principal de la ventana. Gestiona los mensajes del sistema y del usuario.
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        case ID_WBLG_AUTOR:
            Autor(hWnd);
            break;
        case ID_FICHEROS_GUARDARFICHERO:
            GuardarFichero(hWnd);
            break;
        case ID_FICHEROS_ABRIRFICHERO:
        {
            if (AbrirFichero(hWnd)) {
                std::wstringstream mensaje;
                mensaje << L"Archivo cargado en memoria correctamente.\n";
                mensaje << L"Nombre: " << g_nombreFichero.c_str() << L"\n";
                mensaje << L"Tamaño: " << g_tamBufferArchivo << L" bytes\n";
                mensaje << L"Dirección de inicio: 0x" << std::hex << reinterpret_cast<uintptr_t>(g_pBufferArchivo) << L"\n";
                mensaje << L"Dirección de fin: 0x" << std::hex << reinterpret_cast<uintptr_t>(g_pBufferArchivo + g_tamBufferArchivo - 1);
                MessageBox(hWnd, mensaje.str().c_str(), L"Éxito", MB_OK | MB_ICONINFORMATION);

                // Divide en líneas reales
                int numLineas = 1;
                for (wchar_t c : g_contenidoArchivo) if (c == L'\n') ++numLineas;
                SCROLLINFO si = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE, 0, numLineas, 1, 0, 0 };
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

                int maxLen = 0, currLen = 0;
                for (wchar_t c : g_contenidoArchivo) {
                    if (c == L'\n') { if (currLen > maxLen) maxLen = currLen; currLen = 0; }
                    else ++currLen;
                }
                if (currLen > maxLen) maxLen = currLen;
                si.nMin = 0; si.nMax = maxLen; si.nPage = 1;
                SetScrollInfo(hWnd, SB_HORZ, &si, TRUE);

                InvalidateRect(hWnd, nullptr, TRUE);
            }
            else {
                MessageBox(hWnd, L"No se pudo abrir el archivo.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        break;
        case ID_ACCIONES_DESCODIFICAR:
        {
            if (!g_pBufferArchivo || g_tamBufferArchivo == 0) {
                MessageBox(hWnd, L"No hay archivo cargado en memoria.\nPrimero escoja el Archivo a Descodificar", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            std::wstring password = PedirPassword(hWnd);
            if (password.empty()) {
                MessageBox(hWnd, L"Operación cancelada o contraseña vacía.", L"Información", MB_OK | MB_ICONINFORMATION);
                break;
            }

            // Descifra directamente el buffer binario
            std::vector<unsigned char> bufferDescifrado;
            if (DescifrarAES256(g_pBufferArchivo, g_tamBufferArchivo, password, bufferDescifrado)) {
                delete[] g_pBufferArchivo;
                g_tamBufferArchivo = bufferDescifrado.size();
                g_pBufferArchivo = new unsigned char[g_tamBufferArchivo];
                memcpy(g_pBufferArchivo, bufferDescifrado.data(), g_tamBufferArchivo);

                // Vista previa: intenta mostrar como texto
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                try {
                    std::string texto(reinterpret_cast<const char*>(bufferDescifrado.data()), bufferDescifrado.size());
                    g_contenidoArchivo = converter.from_bytes(texto);
                }
                catch (...) {
                    g_contenidoArchivo = L"[No se pudo mostrar el contenido como texto]";
                }

                // Ajuste de scroll y repintado
                int numLineas = 1;
                int maxLen = 0, currLen = 0;
                for (wchar_t c : g_contenidoArchivo) {
                    if (c == L'\n') { ++numLineas; if (currLen > maxLen) maxLen = currLen; currLen = 0; }
                    else ++currLen;
                }
                if (currLen > maxLen) maxLen = currLen;

                HDC hdc = GetDC(hWnd);
                TEXTMETRIC tm;
                GetTextMetrics(hdc, &tm);
                int lineHeight = tm.tmHeight;
                int charWidth = tm.tmAveCharWidth;
                ReleaseDC(hWnd, hdc);

                RECT rect;
                GetClientRect(hWnd, &rect);

                SCROLLINFO si = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE, 0, numLineas, 1, 0, 0 };
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

                si.nMin = 0; si.nMax = maxLen * charWidth; si.nPage = rect.right - rect.left;
                SetScrollInfo(hWnd, SB_HORZ, &si, TRUE);

                MessageBox(hWnd, L"Archivo descodificado correctamente en memoria.", L"Éxito", MB_OK | MB_ICONINFORMATION);
            }
            else {
                MessageBox(hWnd, L"Error al descodificar el archivo (contraseña incorrecta o datos corruptos).", L"Error", MB_OK | MB_ICONERROR);
            }
            InvalidateRect(hWnd, nullptr, TRUE);
        }
        break;
        case ID_ACCIONES_CODIFICAR:
        {
            if (!g_pBufferArchivo || g_tamBufferArchivo == 0) {
                MessageBox(hWnd, L"No hay archivo cargado en memoria.\nPrimero escoja el Archivo a Codificar", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            std::wstring password = PedirPassword(hWnd);
            if (password.empty()) {
                MessageBox(hWnd, L"Operación cancelada o contraseña vacía.", L"Información", MB_OK | MB_ICONINFORMATION);
                break;
            }

            std::vector<unsigned char> bufferCifrado;
            if (CifrarAES256(g_pBufferArchivo, g_tamBufferArchivo, password, bufferCifrado)) {
                delete[] g_pBufferArchivo;
                g_tamBufferArchivo = bufferCifrado.size();
                g_pBufferArchivo = new unsigned char[g_tamBufferArchivo];
                memcpy(g_pBufferArchivo, bufferCifrado.data(), g_tamBufferArchivo);

                // Vista previa en base64
                std::string base64;
                CryptoPP::StringSource ss(
                    bufferCifrado.data(), bufferCifrado.size(), true,
                    new CryptoPP::Base64Encoder(
                        new CryptoPP::StringSink(base64), false
                    )
                );
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                g_contenidoArchivo = converter.from_bytes(base64);

                // Ajuste de scroll y repintado
                HDC hdc = GetDC(hWnd);
                TEXTMETRIC tm;
                GetTextMetrics(hdc, &tm);
                int lineHeight = tm.tmHeight;
                int charWidth = tm.tmAveCharWidth;
                ReleaseDC(hWnd, hdc);

                std::vector<std::wstring> lineas;
                size_t start = 0, end;
                int maxLen = 0;
                while ((end = g_contenidoArchivo.find(L'\n', start)) != std::wstring::npos) {
                    int len = (int)(end - start);
                    if (len > maxLen) maxLen = len;
                    lineas.push_back(g_contenidoArchivo.substr(start, end - start));
                    start = end + 1;
                }
                if (start < g_contenidoArchivo.size()) {
                    int len = (int)(g_contenidoArchivo.size() - start);
                    if (len > maxLen) maxLen = len;
                    lineas.push_back(g_contenidoArchivo.substr(start));
                }
                int numLineas = (int)lineas.size();

                RECT rect;
                GetClientRect(hWnd, &rect);

                SCROLLINFO si = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE, 0, numLineas - 1, (UINT)((rect.bottom - rect.top) / lineHeight), 0, 0 };
                SetScrollInfo(hWnd, SB_VERT, &si, TRUE);

                si.nMin = 0;
                si.nMax = maxLen * charWidth;
                si.nPage = rect.right - rect.left;
                SetScrollInfo(hWnd, SB_HORZ, &si, TRUE);

                MessageBox(hWnd, L"Archivo codificado correctamente en memoria.", L"Éxito", MB_OK | MB_ICONINFORMATION);
            }
            else {
                MessageBox(hWnd, L"Error al codificar el archivo.", L"Error", MB_OK | MB_ICONERROR);
            }
            InvalidateRect(hWnd, nullptr, TRUE);
        }
        break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        int xPos = GetScrollPos(hWnd, SB_HORZ);
        int yPos = GetScrollPos(hWnd, SB_VERT);

        RECT rect;
        GetClientRect(hWnd, &rect);

        TEXTMETRIC tm;
        GetTextMetrics(hdc, &tm);
        int lineHeight = tm.tmHeight;

        // Divide el texto en líneas reales por '\n'
        std::vector<std::wstring> lineas;
        size_t start = 0, end;
        while ((end = g_contenidoArchivo.find(L'\n', start)) != std::wstring::npos) {
            lineas.push_back(g_contenidoArchivo.substr(start, end - start));
            start = end + 1;
        }
        if (start < g_contenidoArchivo.size())
            lineas.push_back(g_contenidoArchivo.substr(start));

        int linesPerPage = (rect.bottom - rect.top) / lineHeight;
        int firstLine = yPos;
        int lastLine = min((int)lineas.size(), firstLine + linesPerPage + 1);

        int y = rect.top;
        for (int i = firstLine; i < lastLine; ++i, y += lineHeight) {
            TextOutW(hdc, rect.left - xPos, y, lineas[i].c_str(), (int)lineas[i].length());
        }

        EndPaint(hWnd, &ps);
    }
    break;
    case WM_VSCROLL:
    {
        int yPos = GetScrollPos(hWnd, SB_VERT);
        int yNewPos = yPos;
        SCROLLINFO si = { sizeof(SCROLLINFO), SIF_ALL };
        GetScrollInfo(hWnd, SB_VERT, &si);
        switch (LOWORD(wParam))
        {
        case SB_LINEUP: yNewPos -= 1; break;
        case SB_LINEDOWN: yNewPos += 1; break;
        case SB_PAGEUP: yNewPos -= si.nPage; break;
        case SB_PAGEDOWN: yNewPos += si.nPage; break;
        case SB_THUMBPOSITION:
        case SB_THUMBTRACK: yNewPos = HIWORD(wParam); break;
        }
        yNewPos = max(0, min(yNewPos, si.nMax - (int)si.nPage + 1));
        SetScrollPos(hWnd, SB_VERT, yNewPos, TRUE);
        InvalidateRect(hWnd, nullptr, TRUE);
        break;
    }
    case WM_HSCROLL:
    {
        int xPos = GetScrollPos(hWnd, SB_HORZ);
        int xNewPos = xPos;
        SCROLLINFO si = { sizeof(SCROLLINFO), SIF_ALL };
        GetScrollInfo(hWnd, SB_HORZ, &si);

        // Obtén el ancho promedio de carácter para un desplazamiento más natural
        HDC hdc = GetDC(hWnd);
        TEXTMETRIC tm;
        GetTextMetrics(hdc, &tm);
        int charWidth = tm.tmAveCharWidth;
        ReleaseDC(hWnd, hdc);

        int step = charWidth * 8; // Desplaza 8 caracteres por línea
        int page = si.nPage > 0 ? si.nPage : step * 4;

        switch (LOWORD(wParam))
        {
        case SB_LINELEFT:  xNewPos -= step; break;
        case SB_LINERIGHT: xNewPos += step; break;
        case SB_PAGELEFT:  xNewPos -= page; break;
        case SB_PAGERIGHT: xNewPos += page; break;
        case SB_THUMBPOSITION:
        case SB_THUMBTRACK: xNewPos = HIWORD(wParam); break;
        }
        xNewPos = max(0, min(xNewPos, si.nMax - (int)si.nPage + 1));
        SetScrollPos(hWnd, SB_HORZ, xNewPos, TRUE);
        InvalidateRect(hWnd, nullptr, TRUE);
        break;
    }
    case WM_LBUTTONDOWN:
        g_dragScroll = true;
        SetCapture(hWnd);
        g_lastMousePos.x = GET_X_LPARAM(lParam);
        g_lastMousePos.y = GET_Y_LPARAM(lParam);
        break;
    case WM_LBUTTONUP:
        g_dragScroll = false;
        ReleaseCapture();
        break;
    case WM_MOUSEMOVE:
        if (g_dragScroll)
        {
            int x = GET_X_LPARAM(lParam);
            int y = GET_Y_LPARAM(lParam);

            int dx = g_lastMousePos.x - x;
            int dy = g_lastMousePos.y - y;

            int xPos = GetScrollPos(hWnd, SB_HORZ);
            int yPos = GetScrollPos(hWnd, SB_VERT);

            SetScrollPos(hWnd, SB_HORZ, xPos + dx, TRUE);
            SetScrollPos(hWnd, SB_VERT, yPos + dy, TRUE);

            g_lastMousePos.x = x;
            g_lastMousePos.y = y;

            InvalidateRect(hWnd, nullptr, TRUE);
        }
        break;
    case WM_DESTROY:
        if (g_pBufferArchivo) {
            delete[] g_pBufferArchivo;
            g_pBufferArchivo = nullptr;
            g_tamBufferArchivo = 0;
        }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void Autor(HWND hWnd)
{
    MessageBoxA(hWnd, "Sergi .S c++ Encriptación AES-256 https://CanalInformatika.es", "https://CanalInformatika.es", MB_OK | MB_ICONINFORMATION);
}

INT_PTR CALLBACK PasswordDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static std::wstring* pPassword = nullptr;
    switch (message)
    {
    case WM_INITDIALOG:
        pPassword = reinterpret_cast<std::wstring*>(lParam);
        SetDlgItemTextW(hDlg, IDC_EDITPASS, L"");
        SetFocus(GetDlgItem(hDlg, IDC_EDITPASS));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_VALIDAR)
        {
            wchar_t buffer[256];
            GetDlgItemTextW(hDlg, IDC_EDITPASS, buffer, 256);
            if (pPassword)
                *pPassword = buffer;
            EndDialog(hDlg, IDC_VALIDAR);
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, IDCANCEL);
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

std::wstring PedirPassword(HWND hWnd)
{
    std::wstring password;
    INT_PTR res = DialogBoxParamW(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hWnd, PasswordDlgProc, reinterpret_cast<LPARAM>(&password));
    if (res == IDC_VALIDAR)
        return password;
    return L"";
}

// Deriva una clave de 256 bits (32 bytes) usando SHA-256 sobre la contraseña proporcionada
void DerivarClaveSHA256(const std::wstring& password, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv)
{
    std::string pwdUtf8(password.begin(), password.end());
    CryptoPP::SHA256 hash;
    key.CleanNew(32);
    hash.CalculateDigest(key, reinterpret_cast<const unsigned char*>(pwdUtf8.data()), pwdUtf8.size());
    CryptoPP::AutoSeededRandomPool prng;
    iv.CleanNew(16);
    prng.GenerateBlock(iv, iv.size());
}

// Cifra un buffer usando AES-256 CBC y almacena el resultado en bufferCifrado
bool CifrarAES256(const unsigned char* buffer, size_t bufferLen, const std::wstring& password, std::vector<unsigned char>& bufferCifrado)
{
    using namespace CryptoPP;
    SecByteBlock key, iv;
    DerivarClaveSHA256(password, key, iv);

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

    bufferCifrado.clear();
    bufferCifrado.insert(bufferCifrado.end(), iv.begin(), iv.end());

    std::string cipher;
    StringSource ss(buffer, bufferLen, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(cipher)
        )
    );

    bufferCifrado.insert(bufferCifrado.end(), cipher.begin(), cipher.end());
    return true;
}
bool DescifrarAES256(const unsigned char* buffer, size_t bufferLen, const std::wstring& password, std::vector<unsigned char>& bufferDescifrado)
{
    using namespace CryptoPP;
    if (bufferLen < 16) return false; // El IV son los primeros 16 bytes

    SecByteBlock key, iv;
    DerivarClaveSHA256(password, key, iv);

    // El IV real está al principio del buffer
    memcpy(iv, buffer, 16);

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

    bufferDescifrado.clear();
    std::string plain;
    try {
        StringSource ss(buffer + 16, bufferLen - 16, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(plain)
            )
        );
    }
    catch (...) {
        return false;
    }
    bufferDescifrado.assign(plain.begin(), plain.end());
    return true;
}