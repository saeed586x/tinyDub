#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <ksmedia.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using json = nlohmann::json;

namespace tiny {

constexpr UINT WM_APP_STATUS = WM_APP + 10;
constexpr int ID_API_KEY = 1001;
constexpr int ID_SHOW_KEY = 1002;
constexpr int ID_TARGET_LANGUAGE = 1003;
constexpr int ID_SAVE_KEY = 1004;
constexpr int ID_FORGET_KEY = 1005;
constexpr int ID_START_STOP = 1006;
constexpr int ID_CLOSE = 1007;
constexpr int ID_VERSION = 1008;
constexpr int ID_STATUS = 1009;
constexpr int ID_CAPTURE = 1010;
constexpr int ID_GEMINI = 1011;
constexpr int ID_OUTPUT = 1012;

struct StatusMessage {
    std::wstring text;
    int target = ID_STATUS;
    bool ok = true;
};

struct Palette {
    COLORREF bg = RGB(14, 16, 20);
    COLORREF panel = RGB(24, 27, 33);
    COLORREF field = RGB(31, 35, 42);
    COLORREF border = RGB(58, 65, 76);
    COLORREF text = RGB(244, 246, 250);
    COLORREF muted = RGB(160, 168, 181);
    COLORREF accent = RGB(78, 137, 255);
    COLORREF accentPressed = RGB(58, 114, 224);
    COLORREF danger = RGB(220, 80, 80);
    COLORREF success = RGB(58, 199, 115);
};
const Palette kColors{};

template <typename T>
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
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
    void reset(T* p = nullptr) {
        if (p_) p_->Release();
        p_ = p;
    }
};

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string base64_encode(const std::vector<std::uint8_t>& data) {
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) v |= static_cast<std::uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) v |= static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(table[(v >> 18) & 63]);
        out.push_back(table[(v >> 12) & 63]);
        out.push_back(i + 1 < data.size() ? table[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < data.size() ? table[v & 63] : '=');
    }
    return out;
}

std::vector<std::uint8_t> base64_decode(const std::string& text) {
    static const std::array<int, 256> lut = [] {
        std::array<int, 256> a{};
        a.fill(-1);
        const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) a[static_cast<unsigned char>(table[i])] = i;
        return a;
    }();
    std::vector<std::uint8_t> out;
    out.reserve((text.size() * 3) / 4);
    std::uint32_t value = 0;
    int bits = -8;
    for (unsigned char c : text) {
        if (c == '=') break;
        const int d = lut[c];
        if (d < 0) continue;
        value = (value << 6) | static_cast<std::uint32_t>(d);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<std::uint8_t>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

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

bool save_secret(const std::string& secret) {
    DATA_BLOB input{};
    DATA_BLOB output{};
    input.cbData = static_cast<DWORD>(secret.size());
    input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(secret.data()));
    if (!CryptProtectData(&input, L"tinyDub Gemini credential", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return false;
    }
    std::ofstream file(credential_path(), std::ios::binary | std::ios::trunc);
    if (!file) {
        LocalFree(output.pbData);
        return false;
    }
    file.write(reinterpret_cast<const char*>(output.pbData), output.cbData);
    const bool ok = static_cast<bool>(file);
    LocalFree(output.pbData);
    return ok;
}

std::optional<std::string> load_secret() {
    std::ifstream file(credential_path(), std::ios::binary);
    if (!file) return std::nullopt;
    std::vector<std::uint8_t> encrypted((std::istreambuf_iterator<char>(file)), {});
    if (encrypted.empty()) return std::nullopt;
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), encrypted.data()};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) return std::nullopt;
    std::string secret(reinterpret_cast<char*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    return secret;
}

bool forget_secret() {
    if (DeleteFileW(credential_path().c_str())) return true;
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

struct AudioBlock {
    std::vector<std::int16_t> pcm;
};

class BlockingAudioQueue {
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<AudioBlock> queue_;
    bool stopped_ = false;
    static constexpr size_t kCapacity = 64;
public:
    bool push(AudioBlock block) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) return false;
        if (queue_.size() >= kCapacity) queue_.pop_front();
        queue_.push_back(std::move(block));
        cv_.notify_one();
        return true;
    }
    bool pop(AudioBlock& block) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return stopped_ || !queue_.empty(); });
        if (queue_.empty()) return false;
        block = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }
    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        cv_.notify_all();
    }
};

class WasapiLoopbackCapture {
    BlockingAudioQueue& output_;
    std::function<void(const std::string&, bool)> status_;
    std::thread thread_;
    std::atomic<bool> running_{false};
public:
    WasapiLoopbackCapture(BlockingAudioQueue& q, std::function<void(const std::string&, bool)> status)
        : output_(q), status_(std::move(status)) {}
    ~WasapiLoopbackCapture() { stop(); }
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
    void report(const char* text, bool ok) { if (status_) status_(text, ok); }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("Audio COM initialization failed", false); return; }

        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) {
            report("Cannot enumerate playback devices", false); return;
        }
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) {
            report("No default playback device found", false); return;
        }
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                                   reinterpret_cast<void**>(client.put())))) {
            report("Cannot open playback stream", false); return;
        }
        WAVEFORMATEX* mix = nullptr;
        if (FAILED(client->GetMixFormat(&mix)) || !mix) { report("Cannot query playback format", false); return; }
        const HRESULT init = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
                                                1000000, 0, mix, nullptr);
        if (FAILED(init)) {
            CoTaskMemFree(mix); report("WASAPI loopback initialization failed", false); return;
        }
        ComPtr<IAudioCaptureClient> capture;
        if (FAILED(client->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(capture.put())))) {
            CoTaskMemFree(mix); report("Cannot open capture service", false); return;
        }
        if (FAILED(client->Start())) {
            CoTaskMemFree(mix); report("Cannot start system audio capture", false); return;
        }

        const int channels = std::max(1, static_cast<int>(mix->nChannels));
        const int sourceRate = std::max(1, static_cast<int>(mix->nSamplesPerSec));
        const bool isFloat =
            mix->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
            (mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
             reinterpret_cast<WAVEFORMATEXTENSIBLE*>(mix)->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        report("System audio capture active", true);

        while (running_) {
            Sleep(8);
            UINT32 frames = 0;
            if (FAILED(capture->GetNextPacketSize(&frames))) break;
            while (frames > 0 && running_) {
                BYTE* data = nullptr;
                DWORD flags = 0;
                UINT32 packetFrames = frames;
                if (FAILED(capture->GetBuffer(&data, &packetFrames, &flags, nullptr, nullptr))) break;

                if (data && packetFrames > 0 && !(flags & AUDCLNT_BUFFERFLAGS_SILENT)) {
                    const double step = static_cast<double>(sourceRate) / 16000.0;
                    const size_t reserveCount = static_cast<size_t>(packetFrames * 16000.0 / sourceRate) + 8;
                    std::vector<std::int16_t> mono(reserveCount);
                    size_t outCount = 0;
                    for (double pos = 0.0; pos + 1.0 < packetFrames; pos += step) {
                        const size_t i = static_cast<size_t>(pos);
                        const double frac = pos - static_cast<double>(i);
                        double value = 0.0;
                        for (int c = 0; c < channels; ++c) {
                            double s0 = 0.0;
                            double s1 = 0.0;
                            if (isFloat) {
                                const float* p = reinterpret_cast<const float*>(data);
                                s0 = p[i * static_cast<size_t>(channels) + static_cast<size_t>(c)];
                                s1 = p[(i + 1) * static_cast<size_t>(channels) + static_cast<size_t>(c)];
                            } else {
                                const std::int16_t* p = reinterpret_cast<const std::int16_t*>(data);
                                s0 = static_cast<double>(p[i * static_cast<size_t>(channels) + static_cast<size_t>(c)]) / 32768.0;
                                s1 = static_cast<double>(p[(i + 1) * static_cast<size_t>(channels) + static_cast<size_t>(c)]) / 32768.0;
                            }
                            value += s0 + (s1 - s0) * frac;
                        }
                        value = std::clamp(value / static_cast<double>(channels), -1.0, 1.0);
                        mono[outCount++] = static_cast<std::int16_t>(std::lrint(value * 32767.0));
                    }
                    mono.resize(outCount);
                    if (!mono.empty()) output_.push(AudioBlock{std::move(mono)});
                }

                capture->ReleaseBuffer(packetFrames);
                if (FAILED(capture->GetNextPacketSize(&frames))) { frames = 0; break; }
            }
        }

        client->Stop();
        CoTaskMemFree(mix);
        if (SUCCEEDED(co)) CoUninitialize();
        report("System audio capture stopped", true);
    }
};

class WasapiRender {
    BlockingAudioQueue queue_;
    std::function<void(const std::string&, bool)> status_;
    std::thread thread_;
    std::atomic<bool> running_{false};
public:
    explicit WasapiRender(std::function<void(const std::string&, bool)> status) : status_(std::move(status)) {}
    ~WasapiRender() { stop(); }
    bool start() {
        if (running_.exchange(true)) return false;
        thread_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        queue_.stop();
        if (thread_.joinable()) thread_.join();
    }
    void push(const std::vector<std::int16_t>& pcm) {
        if (running_ && !pcm.empty()) queue_.push(AudioBlock{pcm});
    }
private:
    void report(const char* text, bool ok) { if (status_) status_(text, ok); }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("Output COM initialization failed", false); return; }
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())))) {
            report("Cannot enumerate output devices", false); return;
        }
        ComPtr<IMMDevice> device;
        if (FAILED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, device.put()))) {
            report("No output device available", false); return;
        }
        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                                    reinterpret_cast<void**>(client.put())))) {
            report("Cannot open output audio client", false); return;
        }

        WAVEFORMATEX format{};
        format.wFormatTag = WAVE_FORMAT_PCM;
        format.nChannels = 1;
        format.nSamplesPerSec = 24000;
        format.wBitsPerSample = 16;
        format.nBlockAlign = 2;
        format.nAvgBytesPerSec = 48000;
        if (FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,
                                       1000000, 0, &format, nullptr))) {
            report("WASAPI translated-audio output initialization failed", false); return;
        }
        ComPtr<IAudioRenderClient> render;
        if (FAILED(client->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(render.put())))) {
            report("Cannot open output render service", false); return;
        }
        UINT32 bufferFrames = 0;
        if (FAILED(client->GetBufferSize(&bufferFrames))) { report("Cannot query output buffer", false); return; }
        if (FAILED(client->Start())) { report("Cannot start translated-audio output", false); return; }
        report("Translated audio output active", true);

        AudioBlock block;
        while (running_) {
            if (!queue_.pop(block)) break;
            size_t offset = 0;
            while (offset < block.pcm.size() && running_) {
                UINT32 padding = 0;
                if (FAILED(client->GetCurrentPadding(&padding))) break;
                const UINT32 available = bufferFrames > padding ? bufferFrames - padding : 0;
                if (available == 0) { Sleep(2); continue; }
                const UINT32 count = static_cast<UINT32>(std::min<size_t>(available, block.pcm.size() - offset));
                BYTE* destination = nullptr;
                if (FAILED(render->GetBuffer(count, &destination))) break;
                std::memcpy(destination, block.pcm.data() + offset, static_cast<size_t>(count) * sizeof(std::int16_t));
                render->ReleaseBuffer(count, 0);
                offset += count;
            }
        }
        client->Stop();
        if (SUCCEEDED(co)) CoUninitialize();
    }
};

class GeminiLiveClient {
    BlockingAudioQueue& input_;
    std::string apiKey_;
    std::string targetLanguage_;
    std::function<void(const std::vector<std::int16_t>&)> onAudio_;
    std::function<void(const std::string&, bool)> onStatus_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    HINTERNET session_ = nullptr;
    HINTERNET connection_ = nullptr;
    HINTERNET websocket_ = nullptr;
public:
    GeminiLiveClient(BlockingAudioQueue& input, std::string key, std::string language,
                     std::function<void(const std::vector<std::int16_t>&)> audio,
                     std::function<void(const std::string&, bool)> status)
        : input_(input), apiKey_(std::move(key)), targetLanguage_(std::move(language)),
          onAudio_(std::move(audio)), onStatus_(std::move(status)) {}
    ~GeminiLiveClient() { stop(); }
    bool start() {
        if (running_.exchange(true)) return false;
        worker_ = std::thread([this] { run(); });
        return true;
    }
    void stop() {
        if (!running_.exchange(false)) return;
        input_.stop();
        if (websocket_) WinHttpWebSocketClose(websocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        if (worker_.joinable()) worker_.join();
        if (websocket_) { WinHttpCloseHandle(websocket_); websocket_ = nullptr; }
        if (connection_) { WinHttpCloseHandle(connection_); connection_ = nullptr; }
        if (session_) { WinHttpCloseHandle(session_); session_ = nullptr; }
    }
private:
    void report(const std::string& text, bool ok) { if (onStatus_) onStatus_(text, ok); }

    bool send_text(const std::string& text) {
        if (!websocket_) return false;
        return WinHttpWebSocketSend(websocket_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                    const_cast<char*>(text.data()), static_cast<DWORD>(text.size())) == NO_ERROR;
    }

    bool send_pcm(const std::vector<std::int16_t>& pcm) {
        if (pcm.empty()) return true;
        std::vector<std::uint8_t> bytes(pcm.size() * sizeof(std::int16_t));
        std::memcpy(bytes.data(), pcm.data(), bytes.size());
        json message = {
            {"realtimeInput", {
                {"audio", {
                    {"data", base64_encode(bytes)},
                    {"mimeType", "audio/pcm;rate=16000"}
                }}
            }}
        };
        return send_text(message.dump());
    }

    void receive_loop() {
        std::string accumulated;
        std::array<char, 65536> buffer{};
        while (running_) {
            DWORD bytesRead = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE type = WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
            const DWORD rc = WinHttpWebSocketReceive(websocket_, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                      &bytesRead, &type);
            if (rc != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
                if (running_) report("Gemini WebSocket closed unexpectedly", false);
                return;
            }
            if (type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
                accumulated.append(buffer.data(), bytesRead);
                continue;
            }
            if (type != WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) continue;
            accumulated.append(buffer.data(), bytesRead);

            try {
                json response = json::parse(accumulated);
                accumulated.clear();

                if (response.contains("setupComplete")) {
                    report("Gemini session connected", true);
                }
                if (response.contains("error")) {
                    report("Gemini API error: " + response["error"].dump(), false);
                    return;
                }
                if (!response.contains("serverContent")) continue;
                const auto& content = response["serverContent"];
                if (content.contains("outputTranscription")) {
                    const auto& t = content["outputTranscription"];
                    if (t.contains("text") && onStatus_) onStatus_("Translation: " + t["text"].get<std::string>(), true);
                }
                if (!content.contains("modelTurn")) continue;
                const auto& parts = content["modelTurn"].value("parts", json::array());
                for (const auto& part : parts) {
                    if (!part.contains("inlineData")) continue;
                    const auto& data = part["inlineData"];
                    if (!data.contains("data")) continue;
                    const auto raw = base64_decode(data["data"].get<std::string>());
                    if (raw.size() < 2) continue;
                    std::vector<std::int16_t> pcm(raw.size() / 2);
                    std::memcpy(pcm.data(), raw.data(), pcm.size() * sizeof(std::int16_t));
                    if (onAudio_) onAudio_(pcm);
                }
            } catch (const json::exception&) {
                if (accumulated.size() > 4u * 1024u * 1024u) {
                    accumulated.clear();
                    report("Gemini sent an oversized or invalid WebSocket message", false);
                    return;
                }
            }
        }
    }

    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        session_ = WinHttpOpen(L"tinyDub/0.4", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session_) { report("WinHTTP initialization failed", false); return; }
        WinHttpSetTimeouts(session_, 5000, 5000, 15000, 5000);

        connection_ = WinHttpConnect(session_, L"generativelanguage.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!connection_) { report("Cannot reach Google Gemini", false); return; }

        const std::wstring endpoint =
            L"/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key=" +
            to_wide(apiKey_);
        HINTERNET request = WinHttpOpenRequest(connection_, L"GET", endpoint.c_str(), nullptr,
                                               WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!request) { report("Cannot create Gemini WebSocket request", false); return; }
        if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
            WinHttpCloseHandle(request); report("WebSocket upgrade setup failed", false); return;
        }
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) {
            WinHttpCloseHandle(request); report("Gemini WebSocket handshake failed", false); return;
        }
        websocket_ = WinHttpWebSocketCompleteUpgrade(request, 0);
        WinHttpCloseHandle(request);
        if (!websocket_) { report("Gemini WebSocket upgrade failed", false); return; }

        const json setup = {
            {"setup", {
                {"model", "models/gemini-3.5-live-translate-preview"},
                {"generationConfig", {
                    {"responseModalities", json::array({"AUDIO"})},
                    {"inputAudioTranscription", json::object()},
                    {"outputAudioTranscription", json::object()},
                    {"translationConfig", {
                        {"targetLanguageCode", targetLanguage_},
                        {"echoTargetLanguage", false}
                    }}
                }}
            }}
        };
        if (!send_text(setup.dump())) { report("Gemini setup message failed", false); return; }

        std::thread receiver([this] { receive_loop(); });
        std::vector<std::int16_t> aggregate;
        aggregate.reserve(1600);
        AudioBlock block;
        report("Streaming system audio to Gemini…", true);

        while (running_) {
            if (!input_.pop(block)) break;
            aggregate.insert(aggregate.end(), block.pcm.begin(), block.pcm.end());
            while (aggregate.size() >= 1600) {
                std::vector<std::int16_t> chunk(aggregate.begin(), aggregate.begin() + 1600);
                aggregate.erase(aggregate.begin(), aggregate.begin() + 1600);
                if (!send_pcm(chunk)) {
                    report("Audio upload to Gemini failed", false);
                    running_ = false;
                    break;
                }
            }
        }

        if (!aggregate.empty() && running_) send_pcm(aggregate);
        running_ = false;
        if (websocket_) WinHttpWebSocketClose(websocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        if (receiver.joinable()) receiver.join();
        if (SUCCEEDED(co)) CoUninitialize();
    }
};

struct Language { const wchar_t* name; const char* code; };
constexpr std::array<Language, 10> kLanguages = {{
    {L"Persian", "fa"}, {L"English", "en"}, {L"German", "de"}, {L"French", "fr"},
    {L"Spanish", "es"}, {L"Arabic", "ar"}, {L"Turkish", "tr"}, {L"Russian", "ru"},
    {L"Japanese", "ja"}, {L"Korean", "ko"}
}};

class App {
    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    HWND apiKey_ = nullptr;
    HWND showKey_ = nullptr;
    HWND language_ = nullptr;
    HWND saveKey_ = nullptr;
    HWND forgetKey_ = nullptr;
    HWND startStop_ = nullptr;
    HWND close_ = nullptr;
    HWND status_ = nullptr;
    HWND capture_ = nullptr;
    HWND gemini_ = nullptr;
    HWND output_ = nullptr;
    bool active_ = false;
    std::unique_ptr<BlockingAudioQueue> inputQueue_;
    std::unique_ptr<WasapiLoopbackCapture> captureEngine_;
    std::unique_ptr<WasapiRender> renderEngine_;
    std::unique_ptr<GeminiLiveClient> geminiEngine_;

public:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        App* self = reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lp);
            self = static_cast<App*>(cs->lpCreateParams);
            self->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            self->create_controls();
        }
        if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
        switch (msg) {
            case WM_COMMAND: self->handle_command(wp); return 0;
            case WM_SIZE: self->layout(); return 0;
            case WM_PAINT: self->paint(); return 0;
            case WM_CTLCOLOREDIT: {
                HDC dc = reinterpret_cast<HDC>(wp);
                SetBkColor(dc, kColors.field); SetTextColor(dc, kColors.text);
                return reinterpret_cast<LRESULT>(self->edit_brush());
            }
            case WM_CTLCOLORLISTBOX: {
                HDC dc = reinterpret_cast<HDC>(wp);
                SetBkColor(dc, kColors.field); SetTextColor(dc, kColors.text);
                return reinterpret_cast<LRESULT>(self->edit_brush());
            }
            case WM_CTLCOLORSTATIC: {
                HDC dc = reinterpret_cast<HDC>(wp);
                SetBkMode(dc, TRANSPARENT); SetTextColor(dc, kColors.text);
                return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
            }
            case WM_APP_STATUS: {
                auto* message = reinterpret_cast<StatusMessage*>(lp);
                if (message) { self->set_component_status(message->target, message->text, message->ok); delete message; }
                return 0;
            }
            case WM_CLOSE: self->stop(); DestroyWindow(hwnd); return 0;
            case WM_DESTROY: PostQuitMessage(0); return 0;
            default: break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    int run(HINSTANCE h) {
        instance_ = h;
        WNDCLASSW wc{};
        wc.hInstance = h;
        wc.lpfnWndProc = WndProc;
        wc.lpszClassName = L"tinyDubStableMain";
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(kColors.bg);
        RegisterClassW(&wc);
        hwnd_ = CreateWindowExW(
            0, wc.lpszClassName, L"tinyDub — Real-time translation",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            CW_USEDEFAULT, CW_USEDEFAULT, 820, 650,
            nullptr, nullptr, h, this);
        if (!hwnd_) return 1;
        ShowWindow(hwnd_, SW_SHOW);
        UpdateWindow(hwnd_);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }

private:
    static HBRUSH edit_brush() {
        static HBRUSH brush = CreateSolidBrush(kColors.field);
        return brush;
    }

    static HFONT make_font(int size, int weight = FW_NORMAL) {
        return CreateFontW(size, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH, L"Segoe UI");
    }

    HWND label(const wchar_t* text) {
        return CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd_, nullptr, instance_, nullptr);
    }

    HWND button(const wchar_t* text, int id) {
        return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                             0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    }

    void create_controls() {
        label(L"Gemini API key");
        apiKey_ = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                                  0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_API_KEY)), instance_, nullptr);
        SendMessageW(apiKey_, EM_SETLIMITTEXT, 4096, 0);
        showKey_ = CreateWindowW(L"BUTTON", L"Show", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_SHOW_KEY)), instance_, nullptr);

        label(L"Target language");
        language_ = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                                  0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_TARGET_LANGUAGE)), instance_, nullptr);
        for (const auto& language : kLanguages)
            SendMessageW(language_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(language.name));
        SendMessageW(language_, CB_SETCURSEL, 0, 0);
        saveKey_ = button(L"Save key", ID_SAVE_KEY);
        forgetKey_ = button(L"Forget key", ID_FORGET_KEY);

        label(L"Current mode");
        label(L"OVERLAY MODE — original system audio remains unchanged");
        label(L"The translated voice is mixed on top of the current playback device.");

        label(L"SOURCE AUDIO");
        capture_ = label(L"Waiting for system playback");
        label(L"GEMINI");
        gemini_ = label(L"Disconnected");
        label(L"OUTPUT AUDIO");
        output_ = label(L"Waiting for translated audio");

        status_ = label(L"Ready — enter your Gemini API key and press Start translation");
        startStop_ = button(L"Start translation", ID_START_STOP);
        close_ = button(L"Close", ID_CLOSE);

        if (const auto key = load_secret()) SetWindowTextW(apiKey_, to_wide(*key).c_str());
        layout();
    }

    void move_control(HWND control, int x, int y, int w, int h) {
        if (control) MoveWindow(control, x, y, w, h, TRUE);
    }

    void layout() {
        if (!hwnd_) return;
        RECT r{}; GetClientRect(hwnd_, &r);
        const int W = r.right;
        const int L = 38;
        const int R = W - 38;
        const int F = R - L;
        move_control(apiKey_, L, 78, F - 92, 38);
        move_control(showKey_, R - 78, 78, 78, 38);
        move_control(language_, L, 148, 255, 38);
        move_control(saveKey_, L + 275, 148, 125, 38);
        move_control(forgetKey_, L + 412, 148, 125, 38);
        move_control(capture_, L + 155, 274, F - 155, 28);
        move_control(gemini_, L + 155, 330, F - 155, 28);
        move_control(output_, L + 155, 386, F - 155, 28);
        move_control(status_, L, 470, F - 280, 45);
        move_control(startStop_, R - 245, 460, 245, 52);
        move_control(close_, R - 100, 535, 100, 38);
    }

    void paint() {
        PAINTSTRUCT ps{}; HDC dc = BeginPaint(hwnd_, &ps);
        RECT r{}; GetClientRect(hwnd_, &r);
        HBRUSH bg = CreateSolidBrush(kColors.bg); FillRect(dc, &r, bg); DeleteObject(bg);
        auto panel = [&](int top, int bottom) {
            RECT p{24, top, r.right - 24, bottom};
            HBRUSH b = CreateSolidBrush(kColors.panel); FillRect(dc, &p, b); DeleteObject(b);
        };
        panel(18, 62); panel(68, 210); panel(222, 430); panel(438, 594);
        SetBkMode(dc, TRANSPARENT);
        HFONT title = make_font(26, FW_SEMIBOLD);
        HFONT old = static_cast<HFONT>(SelectObject(dc, title));
        SetTextColor(dc, kColors.text);
        RECT titleRect{40, 24, r.right - 40, 52};
        DrawTextW(dc, L"tinyDub", -1, &titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        SelectObject(dc, old); DeleteObject(title);

        HFONT sub = make_font(12, FW_NORMAL);
        old = static_cast<HFONT>(SelectObject(dc, sub));
        SetTextColor(dc, kColors.muted);
        RECT subRect{42, 50, r.right - 40, 62};
        DrawTextW(dc, L"Native Windows · Gemini Live audio translation", -1, &subRect, DT_LEFT | DT_SINGLELINE);
        SelectObject(dc, old); DeleteObject(sub);

        HFONT hdr = make_font(14, FW_SEMIBOLD);
        old = static_cast<HFONT>(SelectObject(dc, hdr));
        SetTextColor(dc, kColors.text);
        DrawTextW(dc, L"Gemini API key", -1, &(RECT{40, 84, 260, 106}), DT_LEFT | DT_SINGLELINE);
        DrawTextW(dc, L"Target language", -1, &(RECT{40, 132, 260, 154}), DT_LEFT | DT_SINGLELINE);
        DrawTextW(dc, L"Current mode", -1, &(RECT{40, 178, 220, 200}), DT_LEFT | DT_SINGLELINE);
        DrawTextW(dc, L"OVERLAY", -1, &(RECT{40, 238, 150, 260}), DT_LEFT | DT_SINGLELINE);
        DrawTextW(dc, L"GEMINI", -1, &(RECT{40, 294, 150, 316}), DT_LEFT | DT_SINGLELINE);
        DrawTextW(dc, L"OUTPUT", -1, &(RECT{40, 350, 150, 372}), DT_LEFT | DT_SINGLELINE);
        SelectObject(dc, old); DeleteObject(hdr);

        HFONT note = make_font(12, FW_NORMAL);
        old = static_cast<HFONT>(SelectObject(dc, note));
        SetTextColor(dc, kColors.muted);
        DrawTextW(dc, L"The original application audio is not ducked in Overlay mode.", -1,
                  &(RECT{40, 410, r.right - 40, 430}), DT_LEFT | DT_SINGLELINE);
        SelectObject(dc, old); DeleteObject(note);
        EndPaint(hwnd_, &ps);
    }

    void handle_command(WPARAM wp) {
        const int id = LOWORD(wp);
        if (HIWORD(wp) != BN_CLICKED) return;
        if (id == ID_START_STOP) { active_ ? stop() : start(); return; }
        if (id == ID_SAVE_KEY) { save_key(); return; }
        if (id == ID_FORGET_KEY) { forget_key(); return; }
        if (id == ID_CLOSE) { SendMessageW(hwnd_, WM_CLOSE, 0, 0); return; }
        if (id == ID_SHOW_KEY) {
            const bool visible = SendMessageW(showKey_, BM_GETCHECK, 0, 0) == BST_CHECKED;
            SendMessageW(apiKey_, EM_SETPASSWORDCHAR, visible ? 0 : L'•', 0);
            InvalidateRect(apiKey_, nullptr, TRUE);
        }
    }

    void post_component_status(int target, const std::string& text, bool ok) {
        auto* message = new StatusMessage{to_wide(text), target, ok};
        PostMessageW(hwnd_, WM_APP_STATUS, 0, reinterpret_cast<LPARAM>(message));
    }

    void set_component_status(int target, const std::wstring& text, bool ok) {
        HWND targetWindow = target == ID_CAPTURE ? capture_ : (target == ID_GEMINI ? gemini_ : (target == ID_OUTPUT ? output_ : status_));
        if (targetWindow) SetWindowTextW(targetWindow, text.c_str());
        if (target == ID_STATUS && status_) SetWindowTextW(status_, text.c_str());
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    std::string read_api_key() const {
        const int length = GetWindowTextLengthW(apiKey_);
        std::wstring text(static_cast<size_t>(length), L'\0');
        if (length > 0) GetWindowTextW(apiKey_, text.data(), length + 1);
        return to_utf8(text);
    }

    std::string selected_language() const {
        const int index = static_cast<int>(SendMessageW(language_, CB_GETCURSEL, 0, 0));
        if (index < 0 || index >= static_cast<int>(kLanguages.size())) return "fa";
        return kLanguages[static_cast<size_t>(index)].code;
    }

    void save_key() {
        const std::string key = read_api_key();
        if (key.empty()) { set_component_status(ID_STATUS, L"Enter a Gemini API key first", false); SetFocus(apiKey_); return; }
        set_component_status(ID_STATUS, save_secret(key) ? L"API key saved securely for this Windows user" : L"Could not save the API key", true);
    }

    void forget_key() {
        if (active_) { set_component_status(ID_STATUS, L"Stop translation before forgetting the key", false); return; }
        if (forget_secret()) {
            SetWindowTextW(apiKey_, L"");
            set_component_status(ID_STATUS, L"Saved API key removed", true);
        } else {
            set_component_status(ID_STATUS, L"Could not remove the saved API key", false);
        }
    }

    void start() {
        const std::string key = read_api_key();
        if (key.empty()) { set_component_status(ID_STATUS, L"Enter your Gemini API key to start", false); SetFocus(apiKey_); return; }
        active_ = true;
        SetWindowTextW(startStop_, L"Stop translation");
        EnableWindow(apiKey_, FALSE); EnableWindow(showKey_, FALSE); EnableWindow(language_, FALSE);
        EnableWindow(saveKey_, FALSE); EnableWindow(forgetKey_, FALSE);
        inputQueue_ = std::make_unique<BlockingAudioQueue>();
        renderEngine_ = std::make_unique<WasapiRender>([this](const std::string& s, bool ok) { post_component_status(ID_OUTPUT, s, ok); });
        captureEngine_ = std::make_unique<WasapiLoopbackCapture>(*inputQueue_, [this](const std::string& s, bool ok) { post_component_status(ID_CAPTURE, s, ok); });
        geminiEngine_ = std::make_unique<GeminiLiveClient>(
            *inputQueue_, key, selected_language(),
            [this](const std::vector<std::int16_t>& pcm) {
                if (renderEngine_) renderEngine_->push(pcm);
                post_component_status(ID_OUTPUT, "Translated audio received", true);
            },
            [this](const std::string& s, bool ok) { post_component_status(ID_GEMINI, s, ok); });

        set_component_status(ID_STATUS, L"Starting system audio capture and Gemini…", true);
        set_component_status(ID_CAPTURE, L"Starting…", true);
        set_component_status(ID_GEMINI, L"Connecting…", true);
        set_component_status(ID_OUTPUT, L"Waiting for translated audio…", true);
        renderEngine_->start();
        captureEngine_->start();
        geminiEngine_->start();
    }

    void stop() {
        active_ = false;
        if (captureEngine_) captureEngine_->stop();
        if (inputQueue_) inputQueue_->stop();
        if (geminiEngine_) geminiEngine_->stop();
        if (renderEngine_) renderEngine_->stop();
        captureEngine_.reset(); geminiEngine_.reset(); renderEngine_.reset(); inputQueue_.reset();
        EnableWindow(apiKey_, TRUE); EnableWindow(showKey_, TRUE); EnableWindow(language_, TRUE);
        EnableWindow(saveKey_, TRUE); EnableWindow(forgetKey_, TRUE);
        SetWindowTextW(startStop_, L"Start translation");
        set_component_status(ID_CAPTURE, L"Waiting for system playback", true);
        set_component_status(ID_GEMINI, L"Disconnected", true);
        set_component_status(ID_OUTPUT, L"Waiting for translated audio", true);
        set_component_status(ID_STATUS, L"Stopped — ready to start again", true);
    }
};

} // namespace tiny

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    tiny::App app;
    return app.run(hInstance);
}
