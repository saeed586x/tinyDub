#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <ksmedia.h>
#include <avrt.h>
#include <objbase.h>
#include <propidl.h>
#include <sapi.h>
#include <dpapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <stdint.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <cmath>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std::chrono_literals;

template<class T> class ComPtr {
    T* p_ = nullptr;
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    ComPtr& operator=(ComPtr&& o) noexcept { if (this != &o) { reset(); p_ = o.p_; o.p_ = nullptr; } return *this; }
    T* get() const { return p_; }
    T** put() { reset(); return &p_; }
    void reset(T* p = nullptr) { if (p_) p_->Release(); p_ = p; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
};

static std::string utf8_from_wide(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

static std::wstring wide_from_utf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

static std::string base64_encode(const std::vector<unsigned char>& in) {
    static constexpr char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        if (i + 1 < in.size()) v |= static_cast<uint32_t>(in[i + 1]) << 8;
        if (i + 2 < in.size()) v |= in[i + 2];
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(i + 1 < in.size() ? tbl[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < in.size() ? tbl[v & 63] : '=');
    }
    return out;
}

static std::vector<unsigned char> pcm16le_to_bytes(const std::vector<int16_t>& samples) {
    std::vector<unsigned char> out(samples.size() * sizeof(int16_t));
    if (!samples.empty()) std::memcpy(out.data(), samples.data(), out.size());
    return out;
}

struct AudioBlock {
    std::vector<int16_t> pcm16;
};

class BoundedQueue {
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<AudioBlock> q_;
    const size_t cap_;
    bool stopped_ = false;
public:
    explicit BoundedQueue(size_t cap) : cap_(cap) {}
    bool push(AudioBlock b) {
        std::lock_guard<std::mutex> lk(m_);
        if (stopped_) return false;
        if (q_.size() >= cap_) q_.pop_front();
        q_.push_back(std::move(b));
        cv_.notify_one();
        return true;
    }
    bool pop(AudioBlock& b) {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&] { return stopped_ || !q_.empty(); });
        if (q_.empty()) return false;
        b = std::move(q_.front());
        q_.pop_front();
        return true;
    }
    void stop() {
        std::lock_guard<std::mutex> lk(m_);
        stopped_ = true;
        cv_.notify_all();
    }
};

static std::wstring dpapi_path() {
    wchar_t* app = nullptr;
    PWSTR local = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) {
        std::wstring p(local);
        CoTaskMemFree(local);
        p += L"\\tinyDub";
        CreateDirectoryW(p.c_str(), nullptr);
        p += L"\\credential.bin";
        return p;
    }
    return L"tinyDub.credential.bin";
}

static bool save_api_key_dpapi(const std::string& key) {
    DATA_BLOB in{ static_cast<DWORD>(key.size()), reinterpret_cast<BYTE*>(const_cast<char*>(key.data())) };
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"tinyDub Gemini API key", nullptr, nullptr, nullptr, 0, &out)) return false;
    std::ofstream f(dpapi_path(), std::ios::binary | std::ios::trunc);
    if (!f) { LocalFree(out.pbData); return false; }
    f.write(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return static_cast<bool>(f);
}

static std::optional<std::string> load_api_key_dpapi() {
    std::ifstream f(dpapi_path(), std::ios::binary);
    if (!f) return std::nullopt;
    std::vector<unsigned char> enc((std::istreambuf_iterator<char>(f)), {});
    if (enc.empty()) return std::nullopt;
    DATA_BLOB in{ static_cast<DWORD>(enc.size()), enc.data() }, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return std::nullopt;
    std::string key(reinterpret_cast<char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return key;
}

class WasapiLoopback {
    std::thread thread_;
    std::atomic<bool> running_{false};
    BoundedQueue& out_;
public:
    explicit WasapiLoopback(BoundedQueue& q) : out_(q) {}
    bool start() {
        if (running_.exchange(true)) return false;
        thread_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        if (thread_.joinable()) thread_.join();
    }
    ~WasapiLoopback() { stop(); }
private:
    void run() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return;
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) return;
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) return;
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(client.put())))) return;

        WAVEFORMATEX* mix = nullptr;
        if (FAILED(client->GetMixFormat(&mix)) || !mix) return;
        REFERENCE_TIME buffer = 1000000;
        hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
                                buffer, 0, mix, nullptr);
        if (FAILED(hr)) { CoTaskMemFree(mix); return; }
        UINT32 packetFrames = 0;
        client->GetBufferSize(&packetFrames);
        ComPtr<IAudioCaptureClient> capture;
        if (FAILED(client->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(capture.put())))) { CoTaskMemFree(mix); return; }
        HANDLE ev = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (ev) client->SetEventHandle(ev);
        if (FAILED(client->Start())) { if (ev) CloseHandle(ev); CoTaskMemFree(mix); return; }

        const int channels = std::max<int>(1, mix->nChannels);
        const int srcRate = static_cast<int>(mix->nSamplesPerSec);
        const bool float32 = mix->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
                             (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
                              reinterpret_cast<WAVEFORMATEXTENSIBLE*>(mix)->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        while (running_) {
            if (ev) WaitForSingleObject(ev, 50);
            UINT32 frames = 0;
            DWORD flags = 0;
            BYTE* data = nullptr;
            if (FAILED(capture->GetNextPacketSize(&frames))) break;
            while (frames > 0 && running_) {
                if (FAILED(capture->GetBuffer(&data, &frames, &flags, nullptr, nullptr))) break;
                if (!(flags & AUDCLNT_BUFFERFLAGS_SILENT) && data && frames) {
                    std::vector<int16_t> mono;
                    mono.resize(static_cast<size_t>(frames) * 16000 / std::max(srcRate, 1) + 2);
                    size_t outCount = 0;
                    const double step = static_cast<double>(srcRate) / 16000.0;
                    for (double pos = 0.0; pos + 1.0 < frames; pos += step) {
                        const size_t i = static_cast<size_t>(pos);
                        const double frac = pos - static_cast<double>(i);
                        double sample = 0.0;
                        for (int c = 0; c < channels; ++c) {
                            double s = 0.0;
                            if (float32) {
                                const float* p = reinterpret_cast<const float*>(data);
                                s = p[i * channels + c];
                            } else {
                                const int16_t* p = reinterpret_cast<const int16_t*>(data);
                                s = static_cast<double>(p[i * channels + c]) / 32768.0;
                            }
                            if (i + 1 < frames) {
                                double s2 = 0.0;
                                if (float32) {
                                    const float* p = reinterpret_cast<const float*>(data);
                                    s2 = p[(i + 1) * channels + c];
                                } else {
                                    const int16_t* p = reinterpret_cast<const int16_t*>(data);
                                    s2 = static_cast<double>(p[(i + 1) * channels + c]) / 32768.0;
                                }
                                s = s + (s2 - s) * frac;
                            }
                            sample += s;
                        }
                        sample /= channels;
                        sample = std::clamp(sample, -1.0, 1.0);
                        mono[outCount++] = static_cast<int16_t>(std::lrint(sample * 32767.0));
                    }
                    mono.resize(outCount);
                    if (!mono.empty()) out_.push(AudioBlock{std::move(mono)});
                }
                capture->ReleaseBuffer(frames);
                if (FAILED(capture->GetNextPacketSize(&frames))) break;
            }
        }
        client->Stop();
        if (ev) CloseHandle(ev);
        CoTaskMemFree(mix);
    }
};

struct WsMessage {
    std::string text;
};

class GeminiLiveClient {
    std::thread netThread_;
    std::atomic<bool> running_{false};
    std::string apiKey_;
    std::string targetLanguage_ = "en-US";
    std::function<void(const std::vector<int16_t>&)> onAudio_;
    std::function<void(const std::string&)> onStatus_;
    BoundedQueue& audioQ_;

    HINTERNET session_ = nullptr;
    HINTERNET connect_ = nullptr;
    HINTERNET ws_ = nullptr;

public:
    GeminiLiveClient(BoundedQueue& q, std::string key) : apiKey_(std::move(key)), audioQ_(q) {}
    ~GeminiLiveClient() { stop(); }
    void set_target_language(std::string lang) { targetLanguage_ = std::move(lang); }
    void set_audio_callback(std::function<void(const std::vector<int16_t>&)> cb) { onAudio_ = std::move(cb); }
    void set_status_callback(std::function<void(const std::string&)> cb) { onStatus_ = std::move(cb); }
    bool start() {
        if (running_.exchange(true)) return false;
        netThread_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        if (ws_) WinHttpWebSocketClose(ws_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE, nullptr, 0);
        if (netThread_.joinable()) netThread_.join();
        if (ws_) { WinHttpCloseHandle(ws_); ws_ = nullptr; }
        if (connect_) { WinHttpCloseHandle(connect_); connect_ = nullptr; }
        if (session_) { WinHttpCloseHandle(session_); session_ = nullptr; }
    }
private:
    void status(const std::string& s) { if (onStatus_) onStatus_(s); }
    bool send_text(const std::string& s) {
        if (!ws_) return false;
        return WinHttpWebSocketSend(ws_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                    reinterpret_cast<PVOID>(const_cast<char*>(s.data())), static_cast<DWORD>(s.size())) == NO_ERROR;
    }
    bool send_audio(const std::vector<int16_t>& pcm) {
        if (!ws_ || pcm.empty()) return false;
        auto bytes = pcm16le_to_bytes(pcm);
        json msg = {
            {"realtimeInput", {
                {"mediaChunks", json::array({{{"mimeType", "audio/pcm;rate=16000"}, {"data", base64_encode(bytes)}}})}
            }}
        };
        return send_text(msg.dump());
    }
    bool receive() {
        std::array<char, 65536> buffer{};
        while (running_) {
            DWORD read = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
            DWORD rc = WinHttpWebSocketReceive(ws_, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &type);
            if (rc != NO_ERROR) return false;
            if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return false;
            if (type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) continue;
            if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
                try {
                    json j = json::parse(std::string(buffer.data(), read));
                    if (j.contains("setupComplete")) status("Connected");
                    if (j.contains("serverContent")) {
                        auto sc = j["serverContent"];
                        if (sc.contains("interrupted") && sc["interrupted"].get<bool>()) status("Interrupted");
                        if (sc.contains("modelTurn")) {
                            for (auto& part : sc["modelTurn"]["parts"]) {
                                if (part.contains("inlineData") && part["inlineData"].contains("data")) {
                                    std::string b64 = part["inlineData"]["data"].get<std::string>();
                                    std::vector<unsigned char> raw;
                                    raw.reserve((b64.size() * 3) / 4);
                                    static const std::array<int, 256> T = [] {
                                        std::array<int, 256> a{}; a.fill(-1);
                                        const char* p="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                        for (int i=0;i<64;i++) a[static_cast<unsigned char>(p[i])]=i;
                                        return a;
                                    }();
                                    uint32_t val=0; int valb=-8;
                                    for (unsigned char c : b64) {
                                        if (c=='=') break;
                                        int d=T[c]; if (d<0) continue;
                                        val=(val<<6)|static_cast<uint32_t>(d); valb+=6;
                                        if (valb>=0) { raw.push_back(static_cast<unsigned char>((val>>valb)&0xFF)); valb-=8; }
                                    }
                                    if (raw.size() >= 2) {
                                        std::vector<int16_t> pcm(raw.size()/2);
                                        std::memcpy(pcm.data(), raw.data(), pcm.size()*2);
                                        if (onAudio_) onAudio_(pcm);
                                    }
                                }
                            }
                        }
                    }
                } catch (...) {}
            }
        }
        return false;
    }
    void run() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { status("COM init failed"); return; }
        session_ = WinHttpOpen(L"tinyDub/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_) { status("WinHTTP init failed"); return; }
        WinHttpSetTimeouts(session_, 3000, 3000, 5000, 5000);
        connect_ = WinHttpConnect(session_, L"generativelanguage.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connect_) { status("Gemini connect failed"); return; }
        const wchar_t* path = L"/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";
        std::wstring headers = L"Sec-WebSocket-Protocol: gemini-live-api\r\n";
        std::wstring urlPath = std::wstring(path) + L"?key=" + wide_from_utf8(apiKey_);
        HINTERNET req = WinHttpOpenRequest(connect_, L"GET", urlPath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!req) { status("WebSocket request failed"); return; }
        WinHttpAddRequestHeaders(req, headers.c_str(), static_cast<DWORD>(-1L), WINHTTP_ADDREQ_FLAG_ADD);
        if (WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) == FALSE) { WinHttpCloseHandle(req); status("WebSocket option failed"); return; }
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, nullptr)) { WinHttpCloseHandle(req); status("WebSocket handshake failed"); return; }
        ws_ = WinHttpWebSocketCompleteUpgrade(req, 0);
        WinHttpCloseHandle(req);
        if (!ws_) { status("WebSocket upgrade failed"); return; }
        json setup = {
            {"setup", {
                {"model", "models/gemini-3.5-live-translate-preview"},
                {"generationConfig", {
                    {"responseModalities", json::array({"AUDIO"})},
                    {"translationConfig", {{"targetLanguageCode", targetLanguage_}, {"echoTargetLanguage", false}}}
                }}
            }}
        };
        if (!send_text(setup.dump())) { status("Setup send failed"); return; }
        status("Connecting...");
        std::thread rx([this] { receive(); });
        AudioBlock block;
        while (running_) {
            if (!audioQ_.pop(block)) break;
            if (!send_audio(block.pcm16)) { status("Audio send failed"); break; }
        }
        running_ = false;
        if (rx.joinable()) rx.join();
    }
};

class WasapiRender {
    std::thread thread_;
    std::atomic<bool> running_{false};
    BoundedQueue q_{32};
public:
    bool start() {
        if (running_.exchange(true)) return false;
        thread_ = std::thread([this]{ run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        q_.stop();
        if (thread_.joinable()) thread_.join();
    }
    void push(const std::vector<int16_t>& pcm) { if (running_) q_.push(AudioBlock{pcm}); }
    ~WasapiRender() { stop(); }
private:
    void run() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return;
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) return;
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) return;
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(client.put())))) return;
        WAVEFORMATEX fmt{};
        fmt.wFormatTag = WAVE_FORMAT_PCM;
        fmt.nChannels = 1;
        fmt.nSamplesPerSec = 24000;
        fmt.wBitsPerSample = 16;
        fmt.nBlockAlign = 2;
        fmt.nAvgBytesPerSec = 48000;
        if (FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,
                                       1000000, 0, &fmt, nullptr))) return;
        ComPtr<IAudioRenderClient> render;
        if (FAILED(client->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(render.put())))) return;
        UINT32 bufferFrames=0; client->GetBufferSize(&bufferFrames);
        if (FAILED(client->Start())) return;
        AudioBlock b;
        while (running_) {
            if (!q_.pop(b)) break;
            size_t off=0;
            while (off < b.pcm16.size() && running_) {
                UINT32 padding=0; client->GetCurrentPadding(&padding);
                UINT32 avail=bufferFrames-padding;
                if (avail==0) { Sleep(2); continue; }
                UINT32 n=static_cast<UINT32>(std::min<size_t>(avail, b.pcm16.size()-off));
                BYTE* dst=nullptr;
                if (FAILED(render->GetBuffer(n,&dst))) break;
                std::memcpy(dst,b.pcm16.data()+off,n*2);
                render->ReleaseBuffer(n,0);
                off += n;
            }
        }
        client->Stop();
    }
};

class App {
    HWND hwnd_ = nullptr;
    HWND status_ = nullptr;
    HWND lang_ = nullptr;
    HWND key_ = nullptr;
    HWND startBtn_ = nullptr;
    BoundedQueue audioQ_{24};
    std::unique_ptr<WasapiLoopback> capture_;
    std::unique_ptr<GeminiLiveClient> gemini_;
    WasapiRender render_;
    std::atomic<bool> active_{false};
    std::string apiKey_;
public:
    int run(HINSTANCE h) {
        const wchar_t cls[] = L"tinyDubWindow";
        WNDCLASSW wc{}; wc.hInstance=h; wc.lpfnWndProc=WndProc; wc.lpszClassName=cls;
        wc.hCursor=LoadCursorW(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
        RegisterClassW(&wc);
        hwnd_=CreateWindowExW(0,cls,L"tinyDub",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
                              CW_USEDEFAULT,CW_USEDEFAULT,520,320,nullptr,nullptr,h,this);
        if (!hwnd_) return 1;
        ShowWindow(hwnd_,SW_SHOW); UpdateWindow(hwnd_);
        MSG msg{}; while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);} return 0;
    }
    void init_controls() {
        CreateWindowW(L"STATIC",L"Gemini API key:",WS_CHILD|WS_VISIBLE,20,25,110,22,hwnd_,nullptr,nullptr,nullptr);
        key_=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,135,20,345,28,hwnd_,nullptr,nullptr,nullptr);
        CreateWindowW(L"STATIC",L"Target language:",WS_CHILD|WS_VISIBLE,20,70,110,22,hwnd_,nullptr,nullptr,nullptr);
        lang_=CreateWindowW(L"EDIT",L"en-US",WS_CHILD|WS_VISIBLE|WS_BORDER,135,65,160,28,hwnd_,nullptr,nullptr,nullptr);
        startBtn_=CreateWindowW(L"BUTTON",L"Start",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,20,115,120,34,hwnd_,(HMENU)1001,nullptr,nullptr);
        status_=CreateWindowW(L"STATIC",L"Idle",WS_CHILD|WS_VISIBLE,20,170,460,60,hwnd_,nullptr,nullptr,nullptr);
        auto key=load_api_key_dpapi(); if(key) SetWindowTextW(key_,wide_from_utf8(*key).c_str());
        if (const char* env=std::getenv("GEMINI_API_KEY")) SetWindowTextW(key_,wide_from_utf8(env).c_str());
    }
    void set_status(const std::string& s) { if(status_) SetWindowTextW(status_,wide_from_utf8(s).c_str()); }
    void toggle() {
        if(active_) { stop(); return; }
        wchar_t buf[1024]{}; GetWindowTextW(key_,buf,1024); apiKey_=utf8_from_wide(buf);
        if(apiKey_.empty()){set_status("Enter a Gemini API key."); return;}
        wchar_t lbuf[128]{}; GetWindowTextW(lang_,lbuf,128); std::string lang=utf8_from_wide(lbuf);
        save_api_key_dpapi(apiKey_);
        capture_=std::make_unique<WasapiLoopback>(audioQ_);
        gemini_=std::make_unique<GeminiLiveClient>(audioQ_,apiKey_);
        gemini_->set_target_language(lang.empty()?"en-US":lang);
        gemini_->set_audio_callback([this](const std::vector<int16_t>& pcm){ render_.push(pcm); });
        gemini_->set_status_callback([this](const std::string& s){ PostMessageW(hwnd_,WM_APP+1,0,reinterpret_cast<LPARAM>(new std::string(s))); });
        active_=true; SetWindowTextW(startBtn_,L"Stop"); render_.start(); capture_->start(); gemini_->start(); set_status("Starting capture and translation...");
    }
    void stop() {
        active_=false; if(capture_) capture_->stop(); audioQ_.stop(); if(gemini_) gemini_->stop(); render_.stop(); capture_.reset(); gemini_.reset(); SetWindowTextW(startBtn_,L"Start"); set_status("Stopped");
    }
    static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
        App* self=reinterpret_cast<App*>(GetWindowLongPtrW(w,GWLP_USERDATA));
        if(m==WM_NCCREATE){auto* cs=reinterpret_cast<CREATESTRUCTW*>(lp); self=static_cast<App*>(cs->lpCreateParams); SetWindowLongPtrW(w,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self)); self->hwnd_=w; self->init_controls();}
        if(self){
            if(m==WM_COMMAND && LOWORD(wp)==1001){self->toggle(); return 0;}
            if(m==WM_APP+1){auto* s=reinterpret_cast<std::string*>(lp); self->set_status(*s); delete s; return 0;}
            if(m==WM_CLOSE){self->stop(); DestroyWindow(w); return 0;}
            if(m==WM_DESTROY){PostQuitMessage(0); return 0;}
        }
        return DefWindowProcW(w,m,wp,lp);
    }
};

int APIENTRY wWinMain(HINSTANCE hInst,HINSTANCE,LPWSTR,int){ return App().run(hInst); }
