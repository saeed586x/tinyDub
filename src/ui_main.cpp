#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <ksmedia.h>
#include <avrt.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using namespace std::chrono_literals;

namespace {

constexpr UINT WM_APP_STATUS = WM_APP + 10;
constexpr int IDC_API_KEY = 1001;
constexpr int IDC_SHOW_KEY = 1002;
constexpr int IDC_LANGUAGE = 1003;
constexpr int IDC_START = 1004;
constexpr int IDC_SAVE = 1005;
constexpr int IDC_FORGET = 1006;
constexpr int IDC_CLOSE = 1007;

struct UiMessage { std::wstring text; bool ok = true; };

struct ColorPalette {
    COLORREF bg = RGB(18, 20, 24);
    COLORREF panel = RGB(27, 30, 36);
    COLORREF panel2 = RGB(33, 37, 45);
    COLORREF border = RGB(57, 63, 74);
    COLORREF text = RGB(242, 244, 248);
    COLORREF muted = RGB(160, 168, 181);
    COLORREF accent = RGB(77, 138, 255);
    COLORREF accentHover = RGB(96, 151, 255);
    COLORREF success = RGB(56, 193, 114);
    COLORREF warning = RGB(240, 177, 68);
    COLORREF danger = RGB(225, 83, 83);
};

const ColorPalette kColors{};

std::wstring wide_from_utf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string utf8_from_wide(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string base64_encode(const std::vector<unsigned char>& in) {
    static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        if (i + 1 < in.size()) v |= static_cast<uint32_t>(in[i + 1]) << 8;
        if (i + 2 < in.size()) v |= static_cast<uint32_t>(in[i + 2]);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(i + 1 < in.size() ? tbl[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < in.size() ? tbl[v & 63] : '=');
    }
    return out;
}

std::vector<unsigned char> base64_decode(const std::string& in) {
    static const std::array<int, 256> T = [] {
        std::array<int, 256> a{};
        a.fill(-1);
        const char* p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) a[static_cast<unsigned char>(p[i])] = i;
        return a;
    }();
    std::vector<unsigned char> out;
    out.reserve((in.size() * 3) / 4);
    uint32_t val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        int d = T[c];
        if (d < 0) continue;
        val = (val << 6) | static_cast<uint32_t>(d);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

template<class T>
class ComPtr {
    T* p_ = nullptr;
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) { reset(); p_ = other.p_; other.p_ = nullptr; }
        return *this;
    }
    T* get() const { return p_; }
    T** put() { reset(); return &p_; }
    void reset(T* p = nullptr) { if (p_) p_->Release(); p_ = p; }
    explicit operator bool() const { return p_ != nullptr; }
    T* operator->() const { return p_; }
};

std::wstring credential_path() {
    PWSTR local = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &local)))
        return L"tinyDub.credential.bin";
    std::wstring path(local);
    CoTaskMemFree(local);
    path += L"\\tinyDub";
    CreateDirectoryW(path.c_str(), nullptr);
    path += L"\\credential.bin";
    return path;
}

bool save_secret_dpapi(const std::string& secret) {
    DATA_BLOB in{static_cast<DWORD>(secret.size()), reinterpret_cast<BYTE*>(const_cast<char*>(secret.data()))};
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"tinyDub credential", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return false;
    std::ofstream f(credential_path(), std::ios::binary | std::ios::trunc);
    if (!f) { LocalFree(out.pbData); return false; }
    f.write(reinterpret_cast<const char*>(out.pbData), out.cbData);
    bool ok = static_cast<bool>(f);
    LocalFree(out.pbData);
    return ok;
}

std::optional<std::string> load_secret_dpapi() {
    std::ifstream f(credential_path(), std::ios::binary);
    if (!f) return std::nullopt;
    std::vector<unsigned char> enc((std::istreambuf_iterator<char>(f)), {});
    if (enc.empty()) return std::nullopt;
    DATA_BLOB in{static_cast<DWORD>(enc.size()), enc.data()}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return std::nullopt;
    std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return result;
}

bool forget_secret_dpapi() {
    return DeleteFileW(credential_path()) || GetLastError() == ERROR_FILE_NOT_FOUND;
}

struct AudioBlock { std::vector<int16_t> pcm; };

class AudioQueue {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<AudioBlock> queue_;
    const size_t capacity_ = 32;
    bool stopped_ = false;
public:
    bool push(AudioBlock block) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) return false;
        if (queue_.size() >= capacity_) queue_.erase(queue_.begin());
        queue_.push_back(std::move(block));
        cv_.notify_one();
        return true;
    }
    bool pop(AudioBlock& block) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return stopped_ || !queue_.empty(); });
        if (queue_.empty()) return false;
        block = std::move(queue_.front());
        queue_.erase(queue_.begin());
        return true;
    }
    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        cv_.notify_all();
    }
};

class WasapiLoopback {
    AudioQueue& out_;
    std::function<void(const std::string&)> status_;
    std::thread thread_;
    std::atomic<bool> running_{false};
public:
    WasapiLoopback(AudioQueue& out, std::function<void(const std::string&)> status)
        : out_(out), status_(std::move(status)) {}
    ~WasapiLoopback() { stop(); }
    bool start() {
        if (running_.exchange(true)) return false;
        thread_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        if (thread_.joinable()) thread_.join();
    }
private:
    void report(const std::string& s) { if (status_) status_(s); }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("COM initialization failed"); return; }
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) {
            report("Audio device enumeration failed"); if (SUCCEEDED(co)) CoUninitialize(); return;
        }
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) {
            report("No default playback device found"); if (SUCCEEDED(co)) CoUninitialize(); return;
        }
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                                    reinterpret_cast<void**>(client.put())))) {
            report("Audio client activation failed"); if (SUCCEEDED(co)) CoUninitialize(); return;
        }
        WAVEFORMATEX* mix = nullptr;
        if (FAILED(client->GetMixFormat(&mix)) || !mix) { report("Audio format query failed"); if (SUCCEEDED(co)) CoUninitialize(); return; }
        HRESULT hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
                                        1000000, 0, mix, nullptr);
        if (FAILED(hr)) { CoTaskMemFree(mix); report("WASAPI loopback initialization failed"); if (SUCCEEDED(co)) CoUninitialize(); return; }
        ComPtr<IAudioCaptureClient> capture;
        if (FAILED(client->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(capture.put())))) {
            CoTaskMemFree(mix); report("Audio capture client unavailable"); if (SUCCEEDED(co)) CoUninitialize(); return;
        }
        HANDLE eventHandle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (eventHandle) client->SetEventHandle(eventHandle);
        if (FAILED(client->Start())) {
            if (eventHandle) CloseHandle(eventHandle); CoTaskMemFree(mix);
            report("Audio capture start failed"); if (SUCCEEDED(co)) CoUninitialize(); return;
        }
        const int channels = std::max<int>(1, mix->nChannels);
        const int srcRate = std::max<int>(1, static_cast<int>(mix->nSamplesPerSec));
        const bool isFloat = mix->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
            (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
             reinterpret_cast<WAVEFORMATEXTENSIBLE*>(mix)->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        report("Audio capture active");
        while (running_) {
            if (eventHandle) WaitForSingleObject(eventHandle, 50);
            UINT32 frames = 0;
            if (FAILED(capture->GetNextPacketSize(&frames))) break;
            while (frames > 0 && running_) {
                BYTE* data = nullptr; DWORD flags = 0; UINT32 packetFrames = frames;
                if (FAILED(capture->GetBuffer(&data, &packetFrames, &flags, nullptr, nullptr))) break;
                if (data && packetFrames && !(flags & AUDCLNT_BUFFERFLAGS_SILENT)) {
                    const size_t estimated = static_cast<size_t>(packetFrames) * 16000 / static_cast<size_t>(srcRate) + 4;
                    std::vector<int16_t> out;
                    out.resize(estimated);
                    size_t outCount = 0;
                    const double step = static_cast<double>(srcRate) / 16000.0;
                    for (double pos = 0.0; pos + 1.0 < packetFrames; pos += step) {
                        size_t i = static_cast<size_t>(pos);
                        double frac = pos - static_cast<double>(i);
                        double mono = 0.0;
                        for (int c = 0; c < channels; ++c) {
                            double s0 = 0.0, s1 = 0.0;
                            if (isFloat) {
                                auto* p = reinterpret_cast<const float*>(data);
                                s0 = p[i * channels + c];
                                s1 = p[(i + 1) * channels + c];
                            } else {
                                auto* p = reinterpret_cast<const int16_t*>(data);
                                s0 = static_cast<double>(p[i * channels + c]) / 32768.0;
                                s1 = static_cast<double>(p[(i + 1) * channels + c]) / 32768.0;
                            }
                            mono += s0 + (s1 - s0) * frac;
                        }
                        mono /= static_cast<double>(channels);
                        mono = std::clamp(mono, -1.0, 1.0);
                        out[outCount++] = static_cast<int16_t>(std::lrint(mono * 32767.0));
                    }
                    out.resize(outCount);
                    if (!out.empty()) out_.push(AudioBlock{std::move(out)});
                }
                capture->ReleaseBuffer(packetFrames);
                if (FAILED(capture->GetNextPacketSize(&frames))) { frames = 0; break; }
            }
        }
        client->Stop();
        if (eventHandle) CloseHandle(eventHandle);
        CoTaskMemFree(mix);
        report("Audio capture stopped");
        if (SUCCEEDED(co)) CoUninitialize();
    }
};

class WasapiRender {
    std::unique_ptr<AudioQueue> queue_ = std::make_unique<AudioQueue>();
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::function<void(const std::string&)> status_;
public:
    explicit WasapiRender(std::function<void(const std::string&)> status) : status_(std::move(status)) {}
    ~WasapiRender() { stop(); }
    bool start() {
        if (running_.exchange(true)) return false;
        queue_ = std::make_unique<AudioQueue>();
        thread_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        queue_->stop();
        if (thread_.joinable()) thread_.join();
    }
    void push(const std::vector<int16_t>& pcm) { if (running_) queue_->push(AudioBlock{pcm}); }
private:
    void report(const std::string& s) { if (status_) status_(s); }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("COM initialization failed"); return; }
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) { report("Render device enumeration failed"); return; }
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) { report("No render device found"); return; }
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(client.put())))) { report("Render activation failed"); return; }
        WAVEFORMATEX fmt{};
        fmt.wFormatTag = WAVE_FORMAT_PCM;
        fmt.nChannels = 1;
        fmt.nSamplesPerSec = 24000;
        fmt.wBitsPerSample = 16;
        fmt.nBlockAlign = 2;
        fmt.nAvgBytesPerSec = 48000;
        if (FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,
                                       1000000, 0, &fmt, nullptr))) { report("Render initialization failed"); return; }
        ComPtr<IAudioRenderClient> render;
        if (FAILED(client->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(render.put())))) { report("Render client unavailable"); return; }
        UINT32 bufferFrames = 0; client->GetBufferSize(&bufferFrames);
        if (FAILED(client->Start())) { report("Render start failed"); return; }
        report("Translated audio output active");
        AudioBlock block;
        while (running_) {
            if (!queue_->pop(block)) break;
            size_t offset = 0;
            while (offset < block.pcm.size() && running_) {
                UINT32 padding = 0;
                if (FAILED(client->GetCurrentPadding(&padding))) break;
                UINT32 available = bufferFrames > padding ? bufferFrames - padding : 0;
                if (!available) { Sleep(2); continue; }
                UINT32 frames = static_cast<UINT32>(std::min<size_t>(available, block.pcm.size() - offset));
                BYTE* dst = nullptr;
                if (FAILED(render->GetBuffer(frames, &dst))) break;
                std::memcpy(dst, block.pcm.data() + offset, static_cast<size_t>(frames) * sizeof(int16_t));
                render->ReleaseBuffer(frames, 0);
                offset += frames;
            }
        }
        client->Stop();
        report("Translated audio output stopped");
        if (SUCCEEDED(co)) CoUninitialize();
    }
};

class GeminiLiveClient {
    AudioQueue& queue_;
    std::string apiKey_;
    std::string targetLanguage_;
    std::function<void(const std::vector<int16_t>&)> onAudio_;
    std::function<void(const std::string&)> status_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    HINTERNET session_ = nullptr;
    HINTERNET connect_ = nullptr;
    HINTERNET ws_ = nullptr;
public:
    GeminiLiveClient(AudioQueue& queue, std::string key, std::string target,
                     std::function<void(const std::vector<int16_t>&)> audio,
                     std::function<void(const std::string&)> status)
        : queue_(queue), apiKey_(std::move(key)), targetLanguage_(std::move(target)),
          onAudio_(std::move(audio)), status_(std::move(status)) {}
    ~GeminiLiveClient() { stop(); }
    bool start() {
        if (running_.exchange(true)) return false;
        worker_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        queue_.stop();
        if (ws_) WinHttpWebSocketClose(ws_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        if (worker_.joinable()) worker_.join();
        if (ws_) { WinHttpCloseHandle(ws_); ws_ = nullptr; }
        if (connect_) { WinHttpCloseHandle(connect_); connect_ = nullptr; }
        if (session_) { WinHttpCloseHandle(session_); session_ = nullptr; }
    }
private:
    void report(const std::string& s) { if (status_) status_(s); }
    bool send_text(const std::string& s) {
        if (!ws_) return false;
        return WinHttpWebSocketSend(ws_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                    const_cast<char*>(s.data()), static_cast<DWORD>(s.size())) == NO_ERROR;
    }
    bool send_audio(const std::vector<int16_t>& pcm) {
        if (!ws_ || pcm.empty()) return false;
        std::vector<unsigned char> bytes(pcm.size() * sizeof(int16_t));
        std::memcpy(bytes.data(), pcm.data(), bytes.size());
        json msg = {{"realtimeInput", { {"mediaChunks", json::array({{
            {"mimeType", "audio/pcm;rate=16000"}, {"data", base64_encode(bytes)}
        }})} }}};
        return send_text(msg.dump());
    }
    void receive_loop() {
        std::string accumulated;
        std::array<char, 65536> buffer{};
        while (running_) {
            DWORD read = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
            DWORD rc = WinHttpWebSocketReceive(ws_, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &type);
            if (rc != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
            if (type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
                accumulated.append(buffer.data(), read);
                continue;
            }
            if (type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) continue;
            accumulated.append(buffer.data(), read);
            try {
                json j = json::parse(accumulated);
                accumulated.clear();
                if (j.contains("setupComplete")) report("Connected to Gemini");
                if (!j.contains("serverContent")) continue;
                const auto& sc = j["serverContent"];
                if (sc.contains("interrupted") && sc["interrupted"].is_boolean() && sc["interrupted"].get<bool>()) {
                    report("Gemini interrupted the current turn");
                }
                if (!sc.contains("modelTurn")) continue;
                for (const auto& part : sc["modelTurn"].value("parts", json::array())) {
                    if (!part.contains("inlineData")) continue;
                    const auto& data = part["inlineData"];
                    if (!data.contains("data")) continue;
                    auto raw = base64_decode(data["data"].get<std::string>());
                    if (raw.size() < 2) continue;
                    std::vector<int16_t> pcm(raw.size() / 2);
                    std::memcpy(pcm.data(), raw.data(), pcm.size() * sizeof(int16_t));
                    if (onAudio_) onAudio_(pcm);
                }
            } catch (const json::exception&) {
                if (accumulated.size() > (2u * 1024u * 1024u)) accumulated.clear();
            }
        }
    }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("COM initialization failed"); return; }
        session_ = WinHttpOpen(L"tinyDub/0.2", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_) { report("WinHTTP initialization failed"); return; }
        WinHttpSetTimeouts(session_, 5000, 5000, 10000, 5000);
        connect_ = WinHttpConnect(session_, L"generativelanguage.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connect_) { report("Cannot reach Gemini endpoint"); return; }
        const std::wstring path = L"/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key=" + wide_from_utf8(apiKey_);
        HINTERNET req = WinHttpOpenRequest(connect_, L"GET", path.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!req) { report("WebSocket request creation failed"); return; }
        if (!WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
            WinHttpCloseHandle(req); report("WebSocket upgrade option failed"); return;
        }
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, nullptr)) {
            WinHttpCloseHandle(req); report("Gemini WebSocket handshake failed"); return;
        }
        ws_ = WinHttpWebSocketCompleteUpgrade(req, 0);
        WinHttpCloseHandle(req);
        if (!ws_) { report("Gemini WebSocket upgrade failed"); return; }
        json setup = {{"setup", {
            {"model", "models/gemini-3.5-live-translate-preview"},
            {"generationConfig", {
                {"responseModalities", json::array({"AUDIO"})},
                {"translationConfig", {
                    {"targetLanguageCode", targetLanguage_},
                    {"echoTargetLanguage", false}
                }}
            }}
        }}};
        if (!send_text(setup.dump())) { report("Gemini setup message failed"); return; }
        std::thread receiver([this] { receive_loop(); });
        AudioBlock block;
        while (running_) {
            if (!queue_.pop(block)) break;
            if (!send_audio(block.pcm)) {
                report("Audio upload failed");
                break;
            }
        }
        running_ = false;
        if (ws_) WinHttpWebSocketClose(ws_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        if (receiver.joinable()) receiver.join();
        if (SUCCEEDED(co)) CoUninitialize();
    }
};

struct LangItem { const wchar_t* name; const char* code; };
constexpr std::array<LangItem, 10> kLanguages = {{
    {L"English", "en-US"}, {L"Persian", "fa-IR"}, {L"German", "de-DE"},
    {L"French", "fr-FR"}, {L"Spanish", "es-ES"}, {L"Arabic", "ar-SA"},
    {L"Turkish", "tr-TR"}, {L"Russian", "ru-RU"}, {L"Japanese", "ja-JP"},
    {L"Korean", "ko-KR"}
}};

class Button {
    HWND hwnd_ = nullptr;
public:
    static HWND create(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h) {
        return CreateWindowExW(0, L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            GetModuleHandleW(nullptr), nullptr);
    }
    static void draw(const DRAWITEMSTRUCT& d, bool primary) {
        HDC dc = d.hDC;
        RECT r = d.rcItem;
        COLORREF fill = primary ? kColors.accent : kColors.panel2;
        if (d.itemState & ODS_DISABLED) fill = RGB(65, 69, 77);
        if (d.itemState & ODS_SELECTED) fill = primary ? RGB(61, 119, 220) : RGB(45, 49, 58);
        HBRUSH b = CreateSolidBrush(fill); FillRect(dc, &r, b); DeleteObject(b);
        HPEN p = CreatePen(PS_SOLID, 1, primary ? fill : kColors.border);
        HGDIOBJ old = SelectObject(dc, p); SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, r.left, r.top, r.right, r.bottom, 10, 10);
        SelectObject(dc, old); DeleteObject(p);
        wchar_t text[128]{}; GetWindowTextW(d.hwndItem, text, 128);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, d.itemState & ODS_DISABLED ? RGB(170,170,170) : kColors.text);
        HFONT font = CreateFontW(16,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        HFONT oldFont = static_cast<HFONT>(SelectObject(dc, font));
        DrawTextW(dc, text, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(dc, oldFont); DeleteObject(font);
    }
};

class App {
    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    HWND key_ = nullptr;
    HWND showKey_ = nullptr;
    HWND language_ = nullptr;
    HWND start_ = nullptr;
    HWND save_ = nullptr;
    HWND forget_ = nullptr;
    HWND close_ = nullptr;
    HWND status_ = nullptr;
    HWND statusDot_ = nullptr;
    bool active_ = false;
    std::unique_ptr<AudioQueue> audioQueue_;
    std::unique_ptr<WasapiLoopback> capture_;
    std::unique_ptr<GeminiLiveClient> gemini_;
    std::unique_ptr<WasapiRender> render_;

    int scale(int v) const {
        UINT dpi = GetDpiForWindow(hwnd_);
        return MulDiv(v, static_cast<int>(dpi ? dpi : 96), 96);
    }
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        App* self = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            self = static_cast<App*>(cs->lpCreateParams);
            self->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            self->create_controls();
        }
        if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
        switch (msg) {
        case WM_COMMAND: return self->on_command(wp, lp);
        case WM_DRAWITEM: self->on_draw_item(reinterpret_cast<DRAWITEMSTRUCT*>(lp)); return TRUE;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetBkColor(dc, kColors.bg); SetTextColor(dc, kColors.text);
            return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetBkColor(dc, kColors.panel2); SetTextColor(dc, kColors.text);
            return reinterpret_cast<LRESULT>(self->edit_brush());
        }
        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetBkColor(dc, kColors.panel2); SetTextColor(dc, kColors.text);
            return reinterpret_cast<LRESULT>(self->edit_brush());
        }
        case WM_PAINT: self->paint(); return 0;
        case WM_DPICHANGED: {
            RECT* suggested = reinterpret_cast<RECT*>(lp);
            SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left, suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
            self->layout(); return 0;
        }
        case WM_APP_STATUS: {
            auto* msgObj = reinterpret_cast<UiMessage*>(lp);
            if (msgObj) { self->set_status(msgObj->text, msgObj->ok); delete msgObj; }
            return 0;
        }
        case WM_CLOSE: self->shutdown(); DestroyWindow(hwnd); return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        default: break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    HBRUSH edit_brush() { static HBRUSH b = CreateSolidBrush(kColors.panel2); return b; }
    void post_status(const std::string& s, bool ok = true) {
        if (!hwnd_) return;
        auto* msg = new UiMessage{wide_from_utf8(s), ok};
        PostMessageW(hwnd_, WM_APP_STATUS, 0, reinterpret_cast<LPARAM>(msg));
    }
    void paint() {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd_, &ps);
        RECT client{}; GetClientRect(hwnd_, &client);
        HBRUSH bg = CreateSolidBrush(kColors.bg); FillRect(dc, &client, bg); DeleteObject(bg);
        RECT hero{scale(26),scale(22),client.right-scale(26),scale(106)};
        HBRUSH panel = CreateSolidBrush(kColors.panel); FillRect(dc, &hero, panel); DeleteObject(panel);
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, kColors.text);
        HFONT titleFont = CreateFontW(scale(25),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        HFONT old = static_cast<HFONT>(SelectObject(dc,titleFont));
        RECT title{scale(46),scale(34),client.right-scale(46),scale(68)};
        DrawTextW(dc,L"tinyDub",-1,&title,DT_LEFT|DT_SINGLELINE|DT_VCENTER); SelectObject(dc,old); DeleteObject(titleFont);
        HFONT subFont = CreateFontW(scale(13),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        old = static_cast<HFONT>(SelectObject(dc,subFont)); SetTextColor(dc,kColors.muted);
        RECT sub{scale(48),scale(70),client.right-scale(48),scale(96)};
        DrawTextW(dc,L"Real-time system audio translation · Gemini Live",-1,&sub,DT_LEFT|DT_SINGLELINE|DT_VCENTER); SelectObject(dc,old); DeleteObject(subFont);
        RECT card{scale(26),scale(124),client.right-scale(26),scale(322)};
        panel = CreateSolidBrush(kColors.panel); FillRect(dc,&card,panel); DeleteObject(panel);
        RECT route{scale(26),scale(338),client.right-scale(26),scale(428)};
        panel = CreateSolidBrush(kColors.panel); FillRect(dc,&route,panel); DeleteObject(panel);
        EndPaint(hwnd_, &ps);
    }
    void add_label(const wchar_t* text, int x, int y, int w, int h) {
        CreateWindowW(L"STATIC", text, WS_CHILD|WS_VISIBLE, scale(x),scale(y),scale(w),scale(h), hwnd_, nullptr, instance_, nullptr);
    }
    void create_controls() {
        SetWindowLongPtrW(hwnd_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        add_label(L"Gemini API key", 48, 144, 160, 22);
        key_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,
                               scale(48),scale(169),scale(500),scale(34),hwnd_,reinterpret_cast<HMENU>(IDC_API_KEY),instance_,nullptr);
        SendMessageW(key_, EM_SETLIMITTEXT, 4096, 0);
        showKey_ = CreateWindowW(L"BUTTON", L"Show", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,
                                 scale(558),scale(169),scale(78),scale(34),hwnd_,reinterpret_cast<HMENU>(IDC_SHOW_KEY),instance_,nullptr);
        add_label(L"Target language", 48, 220, 160, 22);
        language_ = CreateWindowW(L"COMBOBOX", L"", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,
                                  scale(48),scale(245),scale(270),scale(160),hwnd_,reinterpret_cast<HMENU>(IDC_LANGUAGE),instance_,nullptr);
        for (const auto& item : kLanguages) SendMessageW(language_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.name));
        SendMessageW(language_, CB_SETCURSEL, 1, 0);
        save_ = Button::create(hwnd_, IDC_SAVE, L"Save key", 342, 245, 130, 38);
        forget_ = Button::create(hwnd_, IDC_FORGET, L"Forget key", 484, 245, 130, 38);
        add_label(L"Routing mode", 48, 294, 120, 22);
        add_label(L"Overlay mode", 180, 294, 140, 22);
        add_label(L"Original audio stays at system volume", 330, 294, 290, 22);
        statusDot_ = CreateWindowW(L"STATIC", L"●", WS_CHILD|WS_VISIBLE, scale(48),scale(352),scale(26),scale(26),hwnd_,nullptr,instance_,nullptr);
        status_ = CreateWindowW(L"STATIC", L"Ready · enter your Gemini API key", WS_CHILD|WS_VISIBLE,
                                scale(76),scale(350),scale(510),scale(28),hwnd_,nullptr,instance_,nullptr);
        start_ = Button::create(hwnd_, IDC_START, L"Start translation", 48, 452, 250, 46);
        close_ = Button::create(hwnd_, IDC_CLOSE, L"Close", 522, 452, 112, 46);
        if (auto secret = load_secret_dpapi()) SetWindowTextW(key_, wide_from_utf8(*secret).c_str());
        layout();
    }
    void layout() {
        InvalidateRect(hwnd_, nullptr, TRUE);
    }
    void on_draw_item(DRAWITEMSTRUCT* d) {
        if (!d) return;
        const bool primary = d->CtlID == IDC_START;
        const bool danger = d->CtlID == IDC_FORGET;
        if (danger) {
            HDC dc=d->hDC; RECT r=d->rcItem; HBRUSH b=CreateSolidBrush(active_?RGB(65,69,77):RGB(48,52,60)); FillRect(dc,&r,b); DeleteObject(b);
            wchar_t text[64]{}; GetWindowTextW(d->hwndItem,text,64); SetBkMode(dc,TRANSPARENT); SetTextColor(dc,kColors.text);
            HFONT f=CreateFontW(16,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI"); HFONT old=static_cast<HFONT>(SelectObject(dc,f)); DrawTextW(dc,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE); SelectObject(dc,old); DeleteObject(f); return;
        }
        Button::draw(*d, primary || d->CtlID == IDC_SAVE);
    }
    LRESULT on_command(WPARAM wp, LPARAM lp) {
        int id = LOWORD(wp);
        if (id == IDC_START && HIWORD(wp) == BN_CLICKED) { active_ ? stop() : start(); return 0; }
        if (id == IDC_SAVE && HIWORD(wp) == BN_CLICKED) { save_key(); return 0; }
        if (id == IDC_FORGET && HIWORD(wp) == BN_CLICKED) { forget_key(); return 0; }
        if (id == IDC_CLOSE && HIWORD(wp) == BN_CLICKED) { SendMessageW(hwnd_, WM_CLOSE, 0, 0); return 0; }
        if (id == IDC_SHOW_KEY && HIWORD(wp) == BN_CLICKED) {
            bool show = SendMessageW(showKey_, BM_GETCHECK, 0, 0) == BST_CHECKED;
            SendMessageW(key_, EM_SETPASSWORDCHAR, show ? 0 : L'•', 0); InvalidateRect(key_,nullptr,TRUE); return 0;
        }
        return DefWindowProcW(hwnd_, WM_COMMAND, wp, lp);
    }
    void set_status(const std::wstring& text, bool ok) {
        if (status_) SetWindowTextW(status_, text.c_str());
        if (statusDot_) {
            SetWindowTextW(statusDot_, ok ? L"●" : L"●");
            HDC dc = GetDC(statusDot_); SetTextColor(dc, ok ? kColors.success : kColors.danger); ReleaseDC(statusDot_, dc);
        }
    }
    std::string selected_language() const {
        int idx = static_cast<int>(SendMessageW(language_, CB_GETCURSEL, 0, 0));
        if (idx < 0 || idx >= static_cast<int>(kLanguages.size())) return "fa-IR";
        return kLanguages[static_cast<size_t>(idx)].code;
    }
    std::string read_key() const {
        int n = GetWindowTextLengthW(key_);
        std::wstring text(static_cast<size_t>(n), L'\0');
        GetWindowTextW(key_, text.data(), n + 1);
        return utf8_from_wide(text);
    }
    void save_key() {
        std::string key = read_key();
        if (key.empty()) { set_status(L"Enter a Gemini API key first", false); return; }
        if (save_secret_dpapi(key)) set_status(L"API key saved securely for this Windows user", true);
        else set_status(L"Could not save the API key", false);
    }
    void forget_key() {
        if (active_) { set_status(L"Stop translation before forgetting the key", false); return; }
        if (forget_secret_dpapi()) { SetWindowTextW(key_, L""); set_status(L"Saved API key removed", true); }
        else set_status(L"Could not remove saved API key", false);
    }
    void start() {
        std::string key = read_key();
        if (key.empty()) { set_status(L"Enter your Gemini API key to start", false); SetFocus(key_); return; }
        audioQueue_ = std::make_unique<AudioQueue>();
        render_ = std::make_unique<WasapiRender>([this](const std::string& s){ post_status(s, true); });
        capture_ = std::make_unique<WasapiLoopback>(*audioQueue_, [this](const std::string& s){ post_status(s, true); });
        gemini_ = std::make_unique<GeminiLiveClient>(*audioQueue_, key, selected_language(),
            [this](const std::vector<int16_t>& pcm){ if (render_) render_->push(pcm); },
            [this](const std::string& s){ post_status(s, true); });
        active_ = true;
        SetWindowTextW(start_, L"Stop translation");
        EnableWindow(save_, FALSE); EnableWindow(forget_, FALSE); EnableWindow(key_, FALSE); EnableWindow(language_, FALSE); EnableWindow(showKey_, FALSE);
        set_status(L"Starting capture and Gemini connection…", true);
        render_->start(); capture_->start(); gemini_->start();
    }
    void stop() {
        active_ = false;
        SetWindowTextW(start_, L"Start translation");
        EnableWindow(save_, TRUE); EnableWindow(forget_, TRUE); EnableWindow(key_, TRUE); EnableWindow(language_, TRUE); EnableWindow(showKey_, TRUE);
        if (capture_) capture_->stop();
        if (audioQueue_) audioQueue_->stop();
        if (gemini_) gemini_->stop();
        if (render_) render_->stop();
        capture_.reset(); gemini_.reset(); render_.reset(); audioQueue_.reset();
        set_status(L"Stopped · ready to start again", true);
    }
    void shutdown() { if (active_) stop(); }
public:
    int run(HINSTANCE h) {
        instance_ = h;
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        WNDCLASSW wc{}; wc.hInstance=h; wc.lpfnWndProc=WndProc; wc.lpszClassName=L"tinyDubMainWindow";
        wc.hCursor=LoadCursorW(nullptr, IDC_ARROW); wc.hbrBackground=CreateSolidBrush(kColors.bg);
        RegisterClassW(&wc);
        hwnd_ = CreateWindowExW(0, wc.lpszClassName, L"tinyDub — Real-time translation",
            WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
            CW_USEDEFAULT,CW_USEDEFAULT,scale(680),scale(560),nullptr,nullptr,h,this);
        if (!hwnd_) return 1;
        ShowWindow(hwnd_, SW_SHOW); UpdateWindow(hwnd_);
        MSG msg{}; while (GetMessageW(&msg,nullptr,0,0)>0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
        return static_cast<int>(msg.wParam);
    }
};

}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    return App().run(hInst);
}
