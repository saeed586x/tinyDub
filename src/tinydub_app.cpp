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
#include <cmath>
#include <condition_variable>
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

namespace tinyDub {

constexpr UINT WM_STATUS = WM_APP + 10;
constexpr int ID_KEY = 1001, ID_SHOW = 1002, ID_LANG = 1003, ID_SAVE = 1004,
              ID_FORGET = 1005, ID_START = 1006, ID_CLOSE = 1007;

template<class T>
class ComPtr {
    T* p_ = nullptr;
public:
    ~ComPtr() { reset(); }
    T* get() const { return p_; }
    T** put() { reset(); return &p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
    void reset(T* p = nullptr) { if (p_) p_->Release(); p_ = p; }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr() = default;
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::string b64_encode(const std::vector<std::uint8_t>& in) {
    static constexpr char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        std::uint32_t v = (std::uint32_t)in[i] << 16;
        if (i + 1 < in.size()) v |= (std::uint32_t)in[i + 1] << 8;
        if (i + 2 < in.size()) v |= in[i + 2];
        out.push_back(t[(v >> 18) & 63]); out.push_back(t[(v >> 12) & 63]);
        out.push_back(i + 1 < in.size() ? t[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < in.size() ? t[v & 63] : '=');
    }
    return out;
}

std::vector<std::uint8_t> b64_decode(const std::string& in) {
    static const std::array<int, 256> lut = [] {
        std::array<int, 256> a{}; a.fill(-1);
        const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) a[(unsigned char)t[i]] = i;
        return a;
    }();
    std::vector<std::uint8_t> out;
    out.reserve(in.size() * 3 / 4);
    std::uint32_t v = 0; int bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        int d = lut[c]; if (d < 0) continue;
        v = (v << 6) | (std::uint32_t)d; bits += 6;
        if (bits >= 0) { out.push_back((std::uint8_t)((v >> bits) & 255)); bits -= 8; }
    }
    return out;
}

std::wstring credential_path() {
    PWSTR base = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &base))) return L"tinyDub.credential";
    std::wstring p(base); CoTaskMemFree(base); p += L"\\tinyDub"; CreateDirectoryW(p.c_str(), nullptr); return p + L"\\credential.bin";
}

bool save_key(const std::string& key) {
    DATA_BLOB in{(DWORD)key.size(), (BYTE*)key.data()}, out{};
    if (!CryptProtectData(&in, L"tinyDub Gemini API key", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    std::ofstream f(credential_path(), std::ios::binary | std::ios::trunc);
    if (!f) { LocalFree(out.pbData); return false; }
    f.write((const char*)out.pbData, out.cbData); bool ok = (bool)f; LocalFree(out.pbData); return ok;
}

std::optional<std::string> load_key() {
    std::ifstream f(credential_path(), std::ios::binary); if (!f) return std::nullopt;
    std::vector<std::uint8_t> enc((std::istreambuf_iterator<char>(f)), {}); if (enc.empty()) return std::nullopt;
    DATA_BLOB in{(DWORD)enc.size(), enc.data()}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return std::nullopt;
    std::string key((const char*)out.pbData, out.cbData); LocalFree(out.pbData); return key;
}

void forget_key_file() { DeleteFileW(credential_path().c_str()); }

struct AudioBlock { std::vector<std::int16_t> pcm; };

class AudioQueue {
    std::mutex m_; std::condition_variable cv_; std::vector<AudioBlock> q_; bool stopped_ = false;
    static constexpr size_t capacity_ = 48;
public:
    bool push(AudioBlock b) {
        std::lock_guard<std::mutex> lock(m_); if (stopped_) return false;
        if (q_.size() >= capacity_) q_.erase(q_.begin()); q_.push_back(std::move(b)); cv_.notify_one(); return true;
    }
    bool pop(AudioBlock& b) {
        std::unique_lock<std::mutex> lock(m_); cv_.wait(lock, [&]{ return stopped_ || !q_.empty(); });
        if (q_.empty()) return false; b = std::move(q_.front()); q_.erase(q_.begin()); return true;
    }
    void stop() { std::lock_guard<std::mutex> lock(m_); stopped_ = true; cv_.notify_all(); }
};

class Capture {
    AudioQueue& out_; std::function<void(const std::string&, bool)> status_; std::thread t_; std::atomic<bool> running_{false};
public:
    Capture(AudioQueue& q, std::function<void(const std::string&, bool)> s) : out_(q), status_(std::move(s)) {}
    ~Capture() { stop(); }
    bool start() { if (running_.exchange(true)) return false; t_ = std::thread([this]{ run(); }); return true; }
    void stop() { if (!running_.exchange(false)) return; if (t_.joinable()) t_.join(); }
private:
    void report(const char* s, bool ok=true) { if (status_) status_(s, ok); }
    void run() {
        HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) { report("Audio COM initialization failed", false); return; }
        ComPtr<IMMDeviceEnumerator> en;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)en.put()))) { report("Cannot access Windows audio", false); return; }
        ComPtr<IMMDevice> dev;
        if (FAILED(en->GetDefaultAudioEndpoint(eRender, eConsole, dev.put()))) { report("No default playback device found", false); return; }
        ComPtr<IAudioClient> client;
        if (FAILED(dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)client.put()))) { report("Cannot open playback device", false); return; }
        WAVEFORMATEX* fmt = nullptr;
        if (FAILED(client->GetMixFormat(&fmt)) || !fmt) { report("Cannot read playback format", false); return; }
        HRESULT hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, 1000000, 0, fmt, nullptr);
        if (FAILED(hr)) { CoTaskMemFree(fmt); report("WASAPI loopback initialization failed", false); return; }
        ComPtr<IAudioCaptureClient> cap;
        if (FAILED(client->GetService(__uuidof(IAudioCaptureClient), (void**)cap.put()))) { CoTaskMemFree(fmt); report("Cannot open loopback capture", false); return; }
        if (FAILED(client->Start())) { CoTaskMemFree(fmt); report("Cannot start system audio capture", false); return; }
        const int channels = std::max(1, (int)fmt->nChannels), rate = std::max(1, (int)fmt->nSamplesPerSec);
        const bool isFloat = fmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
            (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE && reinterpret_cast<WAVEFORMATEXTENSIBLE*>(fmt)->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        if (!isFloat && fmt->wBitsPerSample != 16) { client->Stop(); CoTaskMemFree(fmt); report("Unsupported audio format; Float32 or PCM16 required", false); return; }
        report("System audio capture active");
        while (running_) {
            Sleep(5); UINT32 packets = 0; if (FAILED(cap->GetNextPacketSize(&packets))) break;
            while (packets && running_) {
                BYTE* data=nullptr; DWORD flags=0; UINT32 frames=0;
                if (FAILED(cap->GetBuffer(&data,&frames,&flags,nullptr,nullptr))) break;
                if (data && frames && !(flags & AUDCLNT_BUFFERFLAGS_SILENT)) {
                    double step=(double)rate/16000.0; std::vector<std::int16_t> mono((size_t)(frames/step)+8); size_t n=0;
                    for(double pos=0.0; pos+1.0<frames; pos+=step){size_t i=(size_t)pos;double frac=pos-i,sum=0;
                        for(int c=0;c<channels;++c){double a,b;if(isFloat){auto*p=(const float*)data;a=p[i*channels+c];b=p[(i+1)*channels+c];}else{auto*p=(const std::int16_t*)data;a=p[i*channels+c]/32768.0;b=p[(i+1)*channels+c]/32768.0;}sum+=a+(b-a)*frac;}
                        double v=std::clamp(sum/channels,-1.0,1.0);mono[n++]=(std::int16_t)(v*32767.0);}
                    mono.resize(n); if(!mono.empty())out_.push(AudioBlock{std::move(mono)});
                }
                cap->ReleaseBuffer(frames); if(FAILED(cap->GetNextPacketSize(&packets))) packets=0;
            }
        }
        client->Stop(); CoTaskMemFree(fmt); if(SUCCEEDED(co)) CoUninitialize();
    }
};

class Renderer {
    AudioQueue q_; std::function<void(const std::string&, bool)> status_; std::thread t_; std::atomic<bool> running_{false};
public:
    explicit Renderer(std::function<void(const std::string&, bool)> s):status_(std::move(s)){}
    ~Renderer(){stop();}
    bool start(){if(running_.exchange(true))return false;t_=std::thread([this]{run();});return true;}
    void stop(){if(!running_.exchange(false))return;q_.stop();if(t_.joinable())t_.join();}
    void push(const std::vector<std::int16_t>&pcm){if(running_&&!pcm.empty())q_.push(AudioBlock{pcm});}
private:
    void report(const char*s,bool ok=true){if(status_)status_(s,ok);}
    void run(){
        HRESULT co=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(co)&&co!=RPC_E_CHANGED_MODE){report("Output COM initialization failed",false);return;}
        ComPtr<IMMDeviceEnumerator>en;if(FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator),nullptr,CLSCTX_ALL,__uuidof(IMMDeviceEnumerator),(void**)en.put())))return;
        ComPtr<IMMDevice>dev;if(FAILED(en->GetDefaultAudioEndpoint(eRender,eConsole,dev.put())))return;ComPtr<IAudioClient>client;if(FAILED(dev->Activate(__uuidof(IAudioClient),CLSCTX_ALL,nullptr,(void**)client.put())))return;
        WAVEFORMATEX f{};f.wFormatTag=WAVE_FORMAT_PCM;f.nChannels=1;f.nSamplesPerSec=24000;f.wBitsPerSample=16;f.nBlockAlign=2;f.nAvgBytesPerSec=48000;
        if(FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED,AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,1000000,0,&f,nullptr))) {report("WASAPI output initialization failed",false);return;}
        ComPtr<IAudioRenderClient>render;if(FAILED(client->GetService(__uuidof(IAudioRenderClient),(void**)render.put())))return;UINT32 bufferFrames=0;client->GetBufferSize(&bufferFrames);if(FAILED(client->Start()))return;report("Translated audio output active");
        AudioBlock b;while(running_){if(!q_.pop(b))break;size_t off=0;while(off<b.pcm.size()&&running_){UINT32 pad=0;if(FAILED(client->GetCurrentPadding(&pad)))break;UINT32 avail=bufferFrames>pad?bufferFrames-pad:0;if(!avail){Sleep(2);continue;}UINT32 n=(UINT32)std::min<size_t>(avail,b.pcm.size()-off);BYTE*dst=nullptr;if(FAILED(render->GetBuffer(n,&dst)))break;memcpy(dst,b.pcm.data()+off,n*2);render->ReleaseBuffer(n,0);off+=n;}}
        client->Stop();if(SUCCEEDED(co))CoUninitialize();
    }
};

class GeminiClient {
    AudioQueue& input_; std::string key_, target_; std::function<void(const std::vector<std::int16_t>&)> audio_; std::function<void(const std::string&,bool)> status_;
    std::thread worker_, receiver_; std::atomic<bool> running_{false}, setupComplete_{false}; HINTERNET session_=nullptr, connection_=nullptr, ws_=nullptr;
public:
    GeminiClient(AudioQueue&q,std::string key,std::string target,std::function<void(const std::vector<std::int16_t>&)>a,std::function<void(const std::string&,bool)>s):input_(q),key_(std::move(key)),target_(std::move(target)),audio_(std::move(a)),status_(std::move(s)){}
    ~GeminiClient(){stop();}
    bool start(){if(running_.exchange(true))return false;worker_=std::thread([this]{run();});return true;}
    void stop(){if(!running_.exchange(false))return;input_.stop();if(ws_)WinHttpWebSocketClose(ws_,WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,nullptr,0);if(receiver_.joinable())receiver_.join();if(worker_.joinable())worker_.join();if(ws_){WinHttpCloseHandle(ws_);ws_=nullptr;}if(connection_){WinHttpCloseHandle(connection_);connection_=nullptr;}if(session_){WinHttpCloseHandle(session_);session_=nullptr;}}
private:
    void report(const std::string&s,bool ok=true){if(status_)status_(s,ok);}
    bool sendText(const std::string&s){return ws_&&WinHttpWebSocketSend(ws_,WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,(void*)s.data(),(DWORD)s.size())==NO_ERROR;}
    bool sendPcm(const std::vector<std::int16_t>&pcm){if(pcm.empty())return true;std::vector<std::uint8_t>b(pcm.size()*2);memcpy(b.data(),pcm.data(),b.size());json j={{"realtimeInput",{{"audio",{{"data",b64_encode(b)},{"mimeType","audio/pcm;rate=16000"}}}}}};return sendText(j.dump());}
    void receiveLoop(){std::string assembled;std::array<char,65536>buf{};while(running_){DWORD n=0;WINHTTP_WEB_SOCKET_BUFFER_TYPE type=WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;DWORD rc=WinHttpWebSocketReceive(ws_,buf.data(),(DWORD)buf.size(),&n,&type);if(rc!=NO_ERROR){report("Gemini receive failed: WinHTTP "+std::to_string(rc),false);running_=false;return;}if(type==WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE){running_=false;report("Gemini closed the WebSocket",false);return;}if(type==WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE){assembled.append(buf.data(),n);continue;}if(type!=WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)continue;assembled.append(buf.data(),n);try{json r=json::parse(assembled);assembled.clear();if(r.contains("error")){report("Gemini API error: "+r["error"].dump(),false);running_=false;return;}if(r.contains("setupComplete")){setupComplete_=true;report("Gemini session connected");continue;}if(!r.contains("serverContent"))continue;const auto&c=r["serverContent"];if(c.contains("outputTranscription")&&c["outputTranscription"].contains("text"))report("Translation: "+c["outputTranscription"]["text"].get<std::string>());if(!c.contains("modelTurn"))continue;for(const auto&p:c["modelTurn"].value("parts",json::array())){if(!p.contains("inlineData")||!p["inlineData"].contains("data"))continue;auto raw=b64_decode(p["inlineData"]["data"].get<std::string>());if(raw.size()<2)continue;std::vector<std::int16_t>pcm(raw.size()/2);memcpy(pcm.data(),raw.data(),pcm.size()*2);if(audio_)audio_(pcm);}}catch(const json::exception&){if(assembled.size()>4*1024*1024){report("Gemini returned an oversized message",false);running_=false;return;}}}}
    void run(){
        HRESULT co=CoInitializeEx(nullptr,COINIT_MULTITHREADED);session_=WinHttpOpen(L"tinyDub/0.5",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);if(!session_){report("WinHTTP initialization failed",false);return;}WinHttpSetTimeouts(session_,5000,5000,15000,5000);
        connection_=WinHttpConnect(session_,L"generativelanguage.googleapis.com",INTERNET_DEFAULT_HTTPS_PORT,0);if(!connection_){report("Cannot reach Google Gemini",false);return;}
        std::wstring path=L"/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key="+widen(key_);HINTERNET req=WinHttpOpenRequest(connection_,L"GET",path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);if(!req){report("Cannot create Gemini WebSocket request",false);return;}
        if(!WinHttpSetOption(req,WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,nullptr,0)||!WinHttpSendRequest(req,WINHTTP_NO_ADDITIONAL_HEADERS,0,nullptr,0,0,0)||!WinHttpReceiveResponse(req,nullptr)){WinHttpCloseHandle(req);report("Gemini WebSocket handshake failed",false);return;}ws_=WinHttpWebSocketCompleteUpgrade(req,0);WinHttpCloseHandle(req);if(!ws_){report("Gemini WebSocket upgrade failed",false);return;}
        receiver_=std::thread([this]{receiveLoop();});
        json setup={{"setup",{{"model","models/gemini-3.5-live-translate-preview"},{"generationConfig",{{"responseModalities",json::array({"AUDIO"})},{"inputAudioTranscription",json::object()},{"outputAudioTranscription",json::object()},{"translationConfig",{{"targetLanguageCode",target_},{"echoTargetLanguage",false}}}}}}}};
        if(!sendText(setup.dump())){report("Gemini setup message failed",false);running_=false;return;}report("Waiting for Gemini session setup…");
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);while(running_&&!setupComplete_&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(10));if(!setupComplete_){if(running_)report("Gemini did not confirm session setup",false);running_=false;if(receiver_.joinable())receiver_.join();return;}
        report("Streaming system audio to Gemini…");std::vector<std::int16_t>aggregate;aggregate.reserve(1600);AudioBlock block;while(running_){if(!input_.pop(block))break;aggregate.insert(aggregate.end(),block.pcm.begin(),block.pcm.end());while(aggregate.size()>=1600&&running_){std::vector<std::int16_t>chunk(aggregate.begin(),aggregate.begin()+1600);aggregate.erase(aggregate.begin(),aggregate.begin()+1600);if(!sendPcm(chunk)){report("Audio upload to Gemini failed",false);running_=false;break;}}}
        running_=false;if(ws_)WinHttpWebSocketClose(ws_,WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,nullptr,0);if(receiver_.joinable())receiver_.join();if(SUCCEEDED(co))CoUninitialize();
    }
};

struct Lang{const wchar_t*name;const char*code;};constexpr Lang languages[]={
    {L"Persian (فارسی)","fa"},{L"English","en"},{L"German","de"},{L"French","fr"},{L"Spanish","es"},{L"Arabic","ar"},{L"Turkish","tr"},{L"Russian","ru"}
};

class App {
    HINSTANCE instance_{}; HWND hwnd_{}; HWND key_{},show_{},lang_{},save_{},forget_{},start_{},close_{},src_{},gem_{},out_{},status_{}; bool active_=false;
    std::unique_ptr<AudioQueue> queue_;std::unique_ptr<Capture> capture_;std::unique_ptr<Renderer> renderer_;std::unique_ptr<GeminiClient> gemini_;
public:
    static LRESULT CALLBACK WndProc(HWND w,UINT m,WPARAM wp,LPARAM lp){App*a=(App*)GetWindowLongPtrW(w,GWLP_USERDATA);if(m==WM_NCCREATE){auto*cs=(CREATESTRUCTW*)lp;a=(App*)cs->lpCreateParams;a->hwnd_=w;SetWindowLongPtrW(w,GWLP_USERDATA,(LONG_PTR)a);a->create();}if(!a)return DefWindowProcW(w,m,wp,lp);switch(m){case WM_SIZE:a->layout();return 0;case WM_COMMAND:a->command(wp);return 0;case WM_STATUS:{auto*s=(std::pair<int,std::wstring>*)lp;if(s){a->setText(s->first,s->second);delete s;}return 0;}case WM_CLOSE:a->stop();DestroyWindow(w);return 0;case WM_DESTROY:PostQuitMessage(0);return 0;case WM_CTLCOLORSTATIC:{HDC dc=(HDC)wp;SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(35,39,46));return(LRESULT)GetStockObject(NULL_BRUSH);}case WM_CTLCOLOREDIT:{HDC dc=(HDC)wp;SetBkColor(dc,RGB(250,251,253));SetTextColor(dc,RGB(30,34,40));return(LRESULT)GetStockObject(WHITE_BRUSH);}default:return DefWindowProcW(w,m,wp,lp);}}
    int run(HINSTANCE h){instance_=h;WNDCLASSW wc{};wc.hInstance=h;wc.lpfnWndProc=WndProc;wc.lpszClassName=L"tinyDubApp";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);hwnd_=CreateWindowW(wc.lpszClassName,L"tinyDub — Real-time translation",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,780,620,nullptr,nullptr,h,this);if(!hwnd_)return 1;ShowWindow(hwnd_,SW_SHOW);UpdateWindow(hwnd_);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return(int)msg.wParam;}
private:
    HFONT font(int s,int weight=FW_NORMAL){return CreateFontW(-s,0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");}
    HWND label(const wchar_t*t,int id=-1){return CreateWindowW(L"STATIC",t,WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd_,id>=0?(HMENU)(INT_PTR)id:nullptr,instance_,nullptr);} HWND button(const wchar_t*t,int id){return CreateWindowW(L"BUTTON",t,WS_CHILD|WS_VISIBLE|WS_TABSTOP,0,0,0,0,hwnd_,(HMENU)(INT_PTR)id,instance_,nullptr);} void setFont(HWND w,HFONT f){SendMessageW(w,WM_SETFONT,(WPARAM)f,TRUE);}
    void create(){HFONT r=font(14),b=font(14,FW_SEMIBOLD),title=font(27,FW_SEMIBOLD);HWND t=label(L"tinyDub");setFont(t,title);HWND sub=label(L"Native Windows · Gemini Live audio translation");setFont(sub,r);
        HWND kl=label(L"Gemini API key");setFont(kl,b);key_=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,0,0,0,0,hwnd_,(HMENU)ID_KEY,instance_,nullptr);setFont(key_,r);SendMessageW(key_,EM_SETCUEBANNER,TRUE,(LPARAM)L"Paste your Gemini API key here");SendMessageW(key_,EM_SETLIMITTEXT,4096,0);show_=button(L"Show",ID_SHOW);setFont(show_,r);
        HWND ll=label(L"Target language");setFont(ll,b);lang_=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST,0,0,0,0,hwnd_,(HMENU)ID_LANG,instance_,nullptr);setFont(lang_,r);for(auto&x:languages)SendMessageW(lang_,CB_ADDSTRING,0,(LPARAM)x.name);SendMessageW(lang_,CB_SETCURSEL,0,0);save_=button(L"Save key",ID_SAVE);forget_=button(L"Forget key",ID_FORGET);setFont(save_,r);setFont(forget_,r);
        HWND ml=label(L"Current mode");setFont(ml,b);label(L"Overlay mode — original system audio continues normally");label(L"Translation is mixed on the current Windows output device.");
        HWND sl=label(L"SOURCE AUDIO");setFont(sl,b);src_=label(L"Waiting for system playback");HWND gl=label(L"GEMINI");setFont(gl,b);gem_=label(L"Disconnected");HWND ol=label(L"OUTPUT AUDIO");setFont(ol,b);out_=label(L"Waiting for translated audio");status_=label(L"Ready — enter your API key and press Start translation");setFont(status_,r);start_=button(L"Start translation",ID_START);close_=button(L"Close",ID_CLOSE);setFont(start_,font(15,FW_SEMIBOLD));setFont(close_,r);
        if(auto k=load_key())SetWindowTextW(key_,widen(*k).c_str());layout();
    }
    void mv(HWND w,int x,int y,int cx,int cy){if(w)MoveWindow(w,x,y,cx,cy,TRUE);} void layout(){RECT r{};GetClientRect(hwnd_,&r);int W=r.right,L=36,R=W-36,F=R-L;mv(key_,L,92,F-90,38);mv(show_,R-78,92,78,38);mv(lang_,L,165,250,36);mv(save_,L+270,165,120,36);mv(forget_,L+402,165,120,36);mv(src_,L+160,275,F-160,26);mv(gem_,L+160,335,F-160,44);mv(out_,L+160,395,F-160,26);mv(status_,L,468,F-260,44);mv(start_,R-230,460,230,50);mv(close_,R-100,530,100,36);} 
    void post(int id,const std::string&s){auto*p=new std::pair<int,std::wstring>{id,widen(s)};PostMessageW(hwnd_,WM_STATUS,0,(LPARAM)p);} void setText(int id,const std::wstring&s){HWND h=nullptr;switch(id){case ID_START:h=status_;break;case ID_LANG:h=lang_;break;case ID_KEY:h=key_;break;case 2001:h=src_;break;case 2002:h=gem_;break;case 2003:h=out_;break;default:h=status_;break;}if(h)SetWindowTextW(h,s.c_str());}
    std::string readKey(){int n=GetWindowTextLengthW(key_);std::wstring s((size_t)n,L'\0');if(n)GetWindowTextW(key_,s.data(),n+1);return narrow(s);} int selectedLang(){int i=(int)SendMessageW(lang_,CB_GETCURSEL,0,0);return i<0?0:i;}
    void command(WPARAM wp){if(HIWORD(wp)!=BN_CLICKED)return;int id=LOWORD(wp);if(id==ID_START){active_?stop():start();return;}if(id==ID_CLOSE){SendMessageW(hwnd_,WM_CLOSE,0,0);return;}if(id==ID_SHOW){bool v=SendMessageW(show_,BM_GETCHECK,0,0)==BST_CHECKED;SendMessageW(key_,EM_SETPASSWORDCHAR,v?0:L'•',0);InvalidateRect(key_,nullptr,TRUE);return;}if(id==ID_SAVE){auto k=readKey();if(k.empty()){post(ID_START,"Enter your Gemini API key first");SetFocus(key_);return;}post(ID_START,save_key(k)?"API key saved securely for this Windows user":"Could not save API key");return;}if(id==ID_FORGET){if(active_){post(ID_START,"Stop translation before forgetting the key");return;}forget_key_file();SetWindowTextW(key_,L"");post(ID_START,"Saved API key removed");}}
    void start(){auto k=readKey();if(k.empty()){post(ID_START,"Enter your Gemini API key to start");SetFocus(key_);return;}active_=true;SetWindowTextW(start_,L"Stop translation");EnableWindow(key_,FALSE);EnableWindow(show_,FALSE);EnableWindow(lang_,FALSE);EnableWindow(save_,FALSE);EnableWindow(forget_,FALSE);queue_=std::make_unique<AudioQueue>();renderer_=std::make_unique<Renderer>([this](const std::string&s,bool){post(2003,s);});capture_=std::make_unique<Capture>(*queue_,[this](const std::string&s,bool){post(2001,s);});gemini_=std::make_unique<GeminiClient>(*queue_,k,languages[selectedLang()].code,[this](const std::vector<std::int16_t>&p){if(renderer_)renderer_->push(p);},[this](const std::string&s,bool){post(2002,s);});post(ID_START,"Starting system audio capture and Gemini…");renderer_->start();capture_->start();gemini_->start();}
    void stop(){active_=false;if(gemini_)gemini_->stop();if(capture_)capture_->stop();if(queue_)queue_->stop();if(renderer_)renderer_->stop();gemini_.reset();capture_.reset();renderer_.reset();queue_.reset();EnableWindow(key_,TRUE);EnableWindow(show_,TRUE);EnableWindow(lang_,TRUE);EnableWindow(save_,TRUE);EnableWindow(forget_,TRUE);SetWindowTextW(start_,L"Start translation");post(2001,"Waiting for system playback");post(2002,"Disconnected");post(2003,"Waiting for translated audio");post(ID_START,"Stopped — ready to start again");}
};

} // namespace tinyDub

int APIENTRY wWinMain(HINSTANCE h,HINSTANCE,PWSTR,int){tinyDub::App app;return app.run(h);}
