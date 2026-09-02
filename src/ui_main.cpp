#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
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

namespace {

constexpr UINT WM_APP_STATUS = WM_APP + 10;
constexpr int IDC_API_KEY = 1001;
constexpr int IDC_SHOW_KEY = 1002;
constexpr int IDC_LANGUAGE = 1003;
constexpr int IDC_START = 1004;
constexpr int IDC_SAVE = 1005;
constexpr int IDC_FORGET = 1006;
constexpr int IDC_CLOSE = 1007;
constexpr int IDC_SOURCE_INFO = 1008;
constexpr int IDC_GEMINI_INFO = 1009;
constexpr int IDC_OUTPUT_INFO = 1010;

struct StatusMessage { std::wstring text; bool good; };

struct Palette {
    COLORREF bg = RGB(13,15,18);
    COLORREF panel = RGB(25,28,33);
    COLORREF panel2 = RGB(31,35,42);
    COLORREF border = RGB(54,59,69);
    COLORREF text = RGB(244,246,250);
    COLORREF muted = RGB(158,166,179);
    COLORREF accent = RGB(78,137,255);
    COLORREF accentPressed = RGB(57,112,221);
    COLORREF success = RGB(58,199,115);
    COLORREF danger = RGB(227,87,87);
};
const Palette kColors{};

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

std::string base64_encode(const std::vector<std::uint8_t>& in) {
    static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size()+2)/3)*4);
    for (size_t i=0;i<in.size();i+=3) {
        uint32_t v = static_cast<uint32_t>(in[i]) << 16;
        if (i+1<in.size()) v |= static_cast<uint32_t>(in[i+1]) << 8;
        if (i+2<in.size()) v |= static_cast<uint32_t>(in[i+2]);
        out.push_back(table[(v>>18)&63]);
        out.push_back(table[(v>>12)&63]);
        out.push_back(i+1<in.size()?table[(v>>6)&63]:'=');
        out.push_back(i+2<in.size()?table[v&63]:'=');
    }
    return out;
}

std::vector<std::uint8_t> base64_decode(const std::string& in) {
    static const std::array<int,256> lut = [] {
        std::array<int,256> a{}; a.fill(-1);
        const char* t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for(int i=0;i<64;++i) a[static_cast<unsigned char>(t[i])] = i;
        return a;
    }();
    std::vector<std::uint8_t> out;
    out.reserve((in.size()*3)/4);
    uint32_t v=0; int bits=-8;
    for(unsigned char c: in) {
        if(c=='=') break;
        int d=lut[c]; if(d<0) continue;
        v=(v<<6)|static_cast<uint32_t>(d); bits+=6;
        if(bits>=0){ out.push_back(static_cast<std::uint8_t>((v>>bits)&0xFF)); bits-=8; }
    }
    return out;
}

template<class T>
class ComPtr {
    T* p_ = nullptr;
public:
    ComPtr()=default; ~ComPtr(){reset();}
    ComPtr(const ComPtr&)=delete; ComPtr& operator=(const ComPtr&)=delete;
    ComPtr(ComPtr&& o) noexcept:p_(o.p_){o.p_=nullptr;}
    ComPtr& operator=(ComPtr&& o) noexcept{ if(this!=&o){reset();p_=o.p_;o.p_=nullptr;} return *this; }
    T* get()const{return p_;} T** put(){reset();return &p_;} T* operator->()const{return p_;}
    explicit operator bool()const{return p_!=nullptr;}
    void reset(T* p=nullptr){if(p_)p_->Release();p_=p;}
};

std::wstring credential_path(){
    PWSTR local=nullptr;
    if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_DEFAULT,nullptr,&local))) return L"tinyDub.credential.bin";
    std::wstring p(local); CoTaskMemFree(local); p+=L"\\tinyDub"; CreateDirectoryW(p.c_str(),nullptr); p+=L"\\credential.bin"; return p;
}

bool save_secret(const std::string& secret){
    DATA_BLOB in{static_cast<DWORD>(secret.size()),reinterpret_cast<BYTE*>(const_cast<char*>(secret.data()))},out{};
    if(!CryptProtectData(&in,L"tinyDub credential",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out)) return false;
    std::ofstream f(credential_path(),std::ios::binary|std::ios::trunc);
    if(!f){LocalFree(out.pbData);return false;}
    f.write(reinterpret_cast<const char*>(out.pbData),out.cbData); bool ok=static_cast<bool>(f); LocalFree(out.pbData); return ok;
}

std::optional<std::string> load_secret(){
    std::ifstream f(credential_path(),std::ios::binary); if(!f)return std::nullopt;
    std::vector<std::uint8_t> enc((std::istreambuf_iterator<char>(f)),{}); if(enc.empty())return std::nullopt;
    DATA_BLOB in{static_cast<DWORD>(enc.size()),enc.data()},out{};
    if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,0,&out))return std::nullopt;
    std::string s(reinterpret_cast<char*>(out.pbData),out.cbData); LocalFree(out.pbData); return s;
}

bool forget_secret(){ return DeleteFileW(credential_path().c_str()) || GetLastError()==ERROR_FILE_NOT_FOUND; }

struct AudioBlock{std::vector<std::int16_t> pcm;};

class AudioQueue{
    std::mutex m_; std::condition_variable cv_; std::vector<AudioBlock> q_; bool stopped_=false; static constexpr size_t cap_=32;
public:
    bool push(AudioBlock b){std::lock_guard<std::mutex>l(m_);if(stopped_)return false;if(q_.size()>=cap_)q_.erase(q_.begin());q_.push_back(std::move(b));cv_.notify_one();return true;}
    bool pop(AudioBlock& b){std::unique_lock<std::mutex>l(m_);cv_.wait(l,[&]{return stopped_||!q_.empty();});if(q_.empty())return false;b=std::move(q_.front());q_.erase(q_.begin());return true;}
    void stop(){std::lock_guard<std::mutex>l(m_);stopped_=true;cv_.notify_all();}
};

class WasapiLoopback{
    AudioQueue& out_; std::function<void(const std::string&)> status_; std::thread t_; std::atomic<bool> running_{false};
public:
    WasapiLoopback(AudioQueue&q,std::function<void(const std::string&)>s):out_(q),status_(std::move(s)){} ~WasapiLoopback(){stop();}
    bool start(){if(running_.exchange(true))return false;t_=std::thread([this]{run();});return true;}
    void stop(){if(!running_.exchange(false))return;if(t_.joinable())t_.join();}
private:
    void report(const char*s){if(status_)status_(s);}
    void run(){
        HRESULT co=CoInitializeEx(nullptr,COINIT_MULTITHREADED); if(FAILED(co)&&co!=RPC_E_CHANGED_MODE){report("COM initialization failed");return;}
        ComPtr<IMMDeviceEnumerator> en;
        if(FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator),nullptr,CLSCTX_ALL,__uuidof(IMMDeviceEnumerator),reinterpret_cast<void**>(en.put())))){report("Audio device enumeration failed");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IMMDevice> dev; if(FAILED(en->GetDefaultAudioEndpoint(eRender,eConsole,dev.put()))){report("No default playback device found");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IAudioClient> client; if(FAILED(dev->Activate(__uuidof(IAudioClient),CLSCTX_ALL,nullptr,reinterpret_cast<void**>(client.put())))){report("Audio client activation failed");if(SUCCEEDED(co))CoUninitialize();return;}
        WAVEFORMATEX* mix=nullptr; if(FAILED(client->GetMixFormat(&mix))||!mix){report("Audio format query failed");if(SUCCEEDED(co))CoUninitialize();return;}
        if(FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED,AUDCLNT_STREAMFLAGS_LOOPBACK,1000000,0,mix,nullptr))){CoTaskMemFree(mix);report("WASAPI loopback initialization failed");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IAudioCaptureClient> cap; if(FAILED(client->GetService(__uuidof(IAudioCaptureClient),reinterpret_cast<void**>(cap.put())))){CoTaskMemFree(mix);report("Audio capture service unavailable");if(SUCCEEDED(co))CoUninitialize();return;}
        HANDLE ev=CreateEventW(nullptr,FALSE,FALSE,nullptr); if(ev)client->SetEventHandle(ev); if(FAILED(client->Start())){if(ev)CloseHandle(ev);CoTaskMemFree(mix);report("Audio capture start failed");if(SUCCEEDED(co))CoUninitialize();return;}
        const int ch=std::max(1,(int)mix->nChannels), rate=std::max(1,(int)mix->nSamplesPerSec);
        const bool flt=mix->wFormatTag==WAVE_FORMAT_IEEE_FLOAT||(mix->wFormatTag==WAVE_FORMAT_EXTENSIBLE&&reinterpret_cast<WAVEFORMATEXTENSIBLE*>(mix)->SubFormat==KSDATAFORMAT_SUBTYPE_IEEE_FLOAT);
        report("Capturing system audio…");
        while(running_){
            if(ev)WaitForSingleObject(ev,50); UINT32 frames=0; if(FAILED(cap->GetNextPacketSize(&frames)))break;
            while(frames&&running_){
                BYTE* data=nullptr;DWORD flags=0;UINT32 packet=frames; if(FAILED(cap->GetBuffer(&data,&packet,&flags,nullptr,nullptr)))break;
                if(data&&packet&&!(flags&AUDCLNT_BUFFERFLAGS_SILENT)){
                    const double step=(double)rate/16000.0; size_t est=(size_t)(packet*16000.0/rate)+8; std::vector<std::int16_t> out(est); size_t n=0;
                    for(double pos=0;pos+1.0<packet;pos+=step){size_t i=(size_t)pos;double frac=pos-i,mono=0.0;
                        for(int c=0;c<ch;++c){double s0,s1;if(flt){auto*p=(const float*)data;s0=p[i*ch+c];s1=p[(i+1)*ch+c];}else{auto*p=(const std::int16_t*)data;s0=p[i*ch+c]/32768.0;s1=p[(i+1)*ch+c]/32768.0;}mono+=s0+(s1-s0)*frac;}
                        mono/=ch;mono=std::clamp(mono,-1.0,1.0);out[n++]=(std::int16_t)std::lrint(mono*32767.0);
                    }
                    out.resize(n);if(!out.empty())out_.push(AudioBlock{std::move(out)});
                }
                cap->ReleaseBuffer(packet); if(FAILED(cap->GetNextPacketSize(&frames)))frames=0;
            }
        }
        client->Stop();if(ev)CloseHandle(ev);CoTaskMemFree(mix);if(SUCCEEDED(co))CoUninitialize();report("Capture stopped");
    }
};

class WasapiRender{
    std::unique_ptr<AudioQueue> q_=std::make_unique<AudioQueue>(); std::thread t_; std::atomic<bool> running_{false}; std::function<void(const std::string&)> status_;
public:
    explicit WasapiRender(std::function<void(const std::string&)>s):status_(std::move(s)){} ~WasapiRender(){stop();}
    bool start(){if(running_.exchange(true))return false;q_=std::make_unique<AudioQueue>();t_=std::thread([this]{run();});return true;}
    void stop(){if(!running_.exchange(false))return;q_->stop();if(t_.joinable())t_.join();}
    void push(const std::vector<std::int16_t>&pcm){if(running_&&!pcm.empty())q_->push(AudioBlock{pcm});}
private:
    void report(const char*s){if(status_)status_(s);}
    void run(){
        HRESULT co=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(co)&&co!=RPC_E_CHANGED_MODE){report("Output COM initialization failed");return;}
        ComPtr<IMMDeviceEnumerator>en;if(FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator),nullptr,CLSCTX_ALL,__uuidof(IMMDeviceEnumerator),reinterpret_cast<void**>(en.put())))){report("Output device enumeration failed");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IMMDevice>dev;if(FAILED(en->GetDefaultAudioEndpoint(eRender,eConsole,dev.put()))){report("No output device found");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IAudioClient>client;if(FAILED(dev->Activate(__uuidof(IAudioClient),CLSCTX_ALL,nullptr,reinterpret_cast<void**>(client.put())))){report("Output audio client activation failed");if(SUCCEEDED(co))CoUninitialize();return;}
        WAVEFORMATEX fmt{};fmt.wFormatTag=WAVE_FORMAT_PCM;fmt.nChannels=1;fmt.nSamplesPerSec=24000;fmt.wBitsPerSample=16;fmt.nBlockAlign=2;fmt.nAvgBytesPerSec=48000;
        if(FAILED(client->Initialize(AUDCLNT_SHAREMODE_SHARED,AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,1000000,0,&fmt,nullptr))){report("Output WASAPI initialization failed");if(SUCCEEDED(co))CoUninitialize();return;}
        ComPtr<IAudioRenderClient>render;if(FAILED(client->GetService(__uuidof(IAudioRenderClient),reinterpret_cast<void**>(render.put())))){report("Output render service unavailable");if(SUCCEEDED(co))CoUninitialize();return;}
        UINT32 bufferFrames=0;client->GetBufferSize(&bufferFrames);if(FAILED(client->Start())){report("Output start failed");if(SUCCEEDED(co))CoUninitialize();return;}
        report("Translated audio output ready");AudioBlock b;
        while(running_){if(!q_->pop(b))break;size_t off=0;while(off<b.pcm.size()&&running_){UINT32 pad=0;if(FAILED(client->GetCurrentPadding(&pad)))break;UINT32 avail=bufferFrames>pad?bufferFrames-pad:0;if(!avail){Sleep(2);continue;}UINT32 n=(UINT32)std::min<size_t>(avail,b.pcm.size()-off);BYTE*dst=nullptr;if(FAILED(render->GetBuffer(n,&dst)))break;std::memcpy(dst,b.pcm.data()+off,n*2);render->ReleaseBuffer(n,0);off+=n;}}
        client->Stop();if(SUCCEEDED(co))CoUninitialize();
    }
};

class GeminiLiveClient{
    AudioQueue& input_;std::string key_,target_;std::function<void(const std::vector<std::int16_t>&)> onAudio_;std::function<void(const std::string&,bool)> status_;std::thread worker_;std::atomic<bool>running_{false};HINTERNET session_=nullptr,connect_=nullptr,ws_=nullptr;
public:
    GeminiLiveClient(AudioQueue&q,std::string key,std::string target,std::function<void(const std::vector<std::int16_t>&)>a,std::function<void(const std::string&,bool)>s):input_(q),key_(std::move(key)),target_(std::move(target)),onAudio_(std::move(a)),status_(std::move(s)){}
    ~GeminiLiveClient(){stop();}
    bool start(){if(running_.exchange(true))return false;worker_=std::thread([this]{run();});return true;}
    void stop(){if(!running_.exchange(false))return;input_.stop();if(ws_)WinHttpWebSocketClose(ws_,WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,nullptr,0);if(worker_.joinable())worker_.join();if(ws_){WinHttpCloseHandle(ws_);ws_=nullptr;}if(connect_){WinHttpCloseHandle(connect_);connect_=nullptr;}if(session_){WinHttpCloseHandle(session_);session_=nullptr;}}
private:
    void report(const std::string&s,bool good){if(status_)status_(s,good);}
    bool send_text(const std::string&s){return ws_&&WinHttpWebSocketSend(ws_,WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,const_cast<char*>(s.data()),(DWORD)s.size())==NO_ERROR;}
    bool send_audio(const std::vector<std::int16_t>&pcm){if(!ws_||pcm.empty())return false;std::vector<std::uint8_t>b(pcm.size()*2);std::memcpy(b.data(),pcm.data(),b.size());json msg={{"realtimeInput",{{"audio",{{"mimeType","audio/pcm;rate=16000"},{"data",base64_encode(b)}}}}}};return send_text(msg.dump());}
    void receive_loop(){std::string acc;std::array<char,65536>buf{};while(running_){DWORD read=0;WINHTTP_WEB_SOCKET_BUFFER_TYPE type=WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;DWORD rc=WinHttpWebSocketReceive(ws_,buf.data(),(DWORD)buf.size(),&read,&type);if(rc!=NO_ERROR||type==WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)break;if(type==WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE){acc.append(buf.data(),read);continue;}if(type!=WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)continue;acc.append(buf.data(),read);try{json j=json::parse(acc);acc.clear();if(j.contains("setupComplete"))report("Gemini connected",true);if(!j.contains("serverContent"))continue;const auto&sc=j["serverContent"];if(sc.contains("error"))report(sc["error"].dump(),false);if(!sc.contains("modelTurn"))continue;for(const auto&part:sc["modelTurn"].value("parts",json::array())){if(!part.contains("inlineData"))continue;const auto&d=part["inlineData"];if(!d.contains("data"))continue;auto raw=base64_decode(d["data"].get<std::string>());if(raw.size()<2)continue;std::vector<std::int16_t>pcm(raw.size()/2);std::memcpy(pcm.data(),raw.data(),pcm.size()*2);if(onAudio_)onAudio_(pcm);}}catch(const json::exception&){if(acc.size()>2*1024*1024)acc.clear();}}}
    void run(){
        HRESULT co=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(co)&&co!=RPC_E_CHANGED_MODE){report("Gemini COM initialization failed",false);return;}
        session_=WinHttpOpen(L"tinyDub/0.3",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);if(!session_){report("WinHTTP initialization failed",false);return;}WinHttpSetTimeouts(session_,5000,5000,10000,5000);
        connect_=WinHttpConnect(session_,L"generativelanguage.googleapis.com",INTERNET_DEFAULT_HTTPS_PORT,0);if(!connect_){report("Cannot reach Gemini",false);return;}
        std::wstring path=L"/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key="+wide_from_utf8(key_);HINTERNET req=WinHttpOpenRequest(connect_,L"GET",path.c_str(),nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);if(!req){report("WebSocket request creation failed",false);return;}
        if(!WinHttpSetOption(req,WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,nullptr,0)){WinHttpCloseHandle(req);report("WebSocket upgrade option failed",false);return;}
        if(!WinHttpSendRequest(req,WINHTTP_NO_ADDITIONAL_HEADERS,0,nullptr,0,0,0)||!WinHttpReceiveResponse(req,nullptr)){WinHttpCloseHandle(req);report("Gemini WebSocket handshake failed",false);return;}
        ws_=WinHttpWebSocketCompleteUpgrade(req,0);WinHttpCloseHandle(req);if(!ws_){report("Gemini WebSocket upgrade failed",false);return;}
        json setup={{"setup",{{"model","models/gemini-3.5-live-translate-preview"},{"generationConfig",{{"responseModalities",json::array({"AUDIO"})},{"translationConfig",{{"targetLanguageCode",target_},{"echoTargetLanguage",false}}}}}}}};
        if(!send_text(setup.dump())){report("Gemini setup failed",false);return;}report("Gemini session starting…",true);std::thread rx([this]{receive_loop();});AudioBlock b;while(running_){if(!input_.pop(b))break;if(!send_audio(b.pcm)){report("Audio upload failed",false);break;}}running_=false;if(ws_)WinHttpWebSocketClose(ws_,WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,nullptr,0);if(rx.joinable())rx.join();if(SUCCEEDED(co))CoUninitialize();
    }
};

struct Lang{const wchar_t*name;const char*code;};
constexpr std::array<Lang,10>kLangs={{{L"Persian","fa"},{L"English","en"},{L"German","de"},{L"French","fr"},{L"Spanish","es"},{L"Arabic","ar"},{L"Turkish","tr"},{L"Russian","ru"},{L"Japanese","ja"},{L"Korean","ko"}}};

class App{
    HINSTANCE inst_=nullptr;HWND hwnd_=nullptr;HWND key_=nullptr,show_=nullptr,lang_=nullptr,start_=nullptr,save_=nullptr,forget_=nullptr,close_=nullptr,status_=nullptr,src_=nullptr,gem_=nullptr,out_=nullptr;bool active_=false;std::unique_ptr<AudioQueue>aq_;std::unique_ptr<WasapiLoopback>cap_;std::unique_ptr<WasapiRender>render_;std::unique_ptr<GeminiLiveClient>gemini_;
public:
    static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM w,LPARAM l){App*self=(App*)GetWindowLongPtrW(h,GWLP_USERDATA);if(m==WM_NCCREATE){auto*cs=(CREATESTRUCTW*)l;self=(App*)cs->lpCreateParams;self->hwnd_=h;SetWindowLongPtrW(h,GWLP_USERDATA,(LONG_PTR)self);self->create_controls();}if(!self)return DefWindowProcW(h,m,w,l);switch(m){case WM_COMMAND:return self->command(w);case WM_SIZE:self->layout();return 0;case WM_PAINT:self->paint();return 0;case WM_CTLCOLOREDIT:{HDC dc=(HDC)w;SetBkColor(dc,kColors.panel2);SetTextColor(dc,kColors.text);return(LRESULT)self->brush();}case WM_CTLCOLORLISTBOX:{HDC dc=(HDC)w;SetBkColor(dc,kColors.panel2);SetTextColor(dc,kColors.text);return(LRESULT)self->brush();}case WM_CTLCOLORSTATIC:{HDC dc=(HDC)w;SetBkMode(dc,TRANSPARENT);SetTextColor(dc,kColors.text);return(LRESULT)GetStockObject(NULL_BRUSH);}case WM_APP_STATUS:{auto*sm=(StatusMessage*)l;if(sm){self->set_status(sm->text,sm->good);delete sm;}return 0;}case WM_CLOSE:self->shutdown();DestroyWindow(h);return 0;case WM_DESTROY:PostQuitMessage(0);return 0;default:return DefWindowProcW(h,m,w,l);}}
    int run(HINSTANCE h){inst_=h;SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);WNDCLASSW wc{};wc.hInstance=h;wc.lpfnWndProc=WndProc;wc.lpszClassName=L"tinyDubMainWindow";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=CreateSolidBrush(kColors.bg);RegisterClassW(&wc);hwnd_=CreateWindowExW(0,wc.lpszClassName,L"tinyDub — Real-time translation",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,760,610,nullptr,nullptr,h,this);if(!hwnd_)return 1;ShowWindow(hwnd_,SW_SHOW);UpdateWindow(hwnd_);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return(int)msg.wParam;}
private:
    HBRUSH brush(){static HBRUSH b=CreateSolidBrush(kColors.panel2);return b;}
    HFONT make_font(int sz,int wt=FW_NORMAL){return CreateFontW(sz,0,0,0,wt,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");}
    HWND st(const wchar_t*t){return CreateWindowW(L"STATIC",t,WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd_,nullptr,inst_,nullptr);}
    HWND btn(const wchar_t*t,int id){return CreateWindowW(L"BUTTON",t,WS_CHILD|WS_VISIBLE|WS_TABSTOP,0,0,0,0,hwnd_,(HMENU)(INT_PTR)id,inst_,nullptr);}
    void create_controls(){
        st(L"Gemini API key");key_=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL,0,0,0,0,hwnd_,(HMENU)IDC_API_KEY,inst_,nullptr);SendMessageW(key_,EM_SETLIMITTEXT,4096,0);
        show_=CreateWindowW(L"BUTTON",L"Show",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX,0,0,0,0,hwnd_,(HMENU)IDC_SHOW_KEY,inst_,nullptr);
        st(L"Target language");lang_=CreateWindowW(L"COMBOBOX",L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,0,0,0,0,hwnd_,(HMENU)IDC_LANGUAGE,inst_,nullptr);for(auto&x:kLangs)SendMessageW(lang_,CB_ADDSTRING,0,(LPARAM)x.name);SendMessageW(lang_,CB_SETCURSEL,0,0);
        save_=btn(L"Save key",IDC_SAVE);forget_=btn(L"Forget key",IDC_FORGET);
        st(L"Current routing");st(L"Overlay mode — original audio remains under Windows/system control");
        st(L"SOURCE AUDIO");src_=st(L"Waiting for system playback");st(L"GEMINI");gem_=st(L"Disconnected");st(L"OUTPUT AUDIO");out_=st(L"Waiting for translated audio");
        status_=st(L"Ready · enter your Gemini API key");start_=btn(L"Start translation",IDC_START);close_=btn(L"Close",IDC_CLOSE);
        if(auto s=load_secret())SetWindowTextW(key_,wide_from_utf8(*s).c_str());layout();
    }
    void mv(HWND w,int x,int y,int cx,int cy){if(w)MoveWindow(w,x,y,cx,cy,TRUE);}
    void layout(){if(!hwnd_)return;RECT r{};GetClientRect(hwnd_,&r);int W=r.right,left=36,right=W-36,field=right-left;mv(key_,left,78,field-90,36);mv(show_,right-78,78,78,36);mv(lang_,left,152,250,36);mv(save_,left+270,152,120,38);mv(forget_,left+402,152,120,38);mv(src_,left+160,250,field-160,28);mv(gem_,left+160,306,field-160,28);mv(out_,left+160,362,field-160,28);mv(status_,left,458,field-250,30);mv(start_,right-230,450,230,46);mv(close_,right-100,510,100,36);}
    void paint(){PAINTSTRUCT ps{};HDC dc=BeginPaint(hwnd_,&ps);RECT r{};GetClientRect(hwnd_,&r);HBRUSH bg=CreateSolidBrush(kColors.bg);FillRect(dc,&r,bg);DeleteObject(bg);auto panel=[&](int t,int b){RECT p{24,t,r.right-24,b};HBRUSH x=CreateSolidBrush(kColors.panel);FillRect(dc,&p,x);DeleteObject(x);};panel(20,62);panel(68,214);panel(224,430);panel(438,568);SetBkMode(dc,TRANSPARENT);HFONT f=make_font(25,FW_SEMIBOLD),old=(HFONT)SelectObject(dc,f);SetTextColor(dc,kColors.text);DrawTextW(dc,L"tinyDub",-1,&(RECT{40,28,r.right-40,58}),DT_LEFT|DT_VCENTER|DT_SINGLELINE);SelectObject(dc,old);DeleteObject(f);f=make_font(14,FW_SEMIBOLD);old=(HFONT)SelectObject(dc,f);DrawTextW(dc,L"Gemini API key",-1,&(RECT{40,82,220,103}),DT_LEFT|DT_SINGLELINE);DrawTextW(dc,L"Target language",-1,&(RECT{40,136,220,157}),DT_LEFT|DT_SINGLELINE);DrawTextW(dc,L"Current routing",-1,&(RECT{40,183,210,204}),DT_LEFT|DT_SINGLELINE);DrawTextW(dc,L"OVERLAY",-1,&(RECT{40,234,130,255}),DT_LEFT|DT_SINGLELINE);DrawTextW(dc,L"GEMINI",-1,&(RECT{40,290,130,311}),DT_LEFT|DT_SINGLELINE);DrawTextW(dc,L"OUTPUT",-1,&(RECT{40,346,130,367}),DT_LEFT|DT_SINGLELINE);SelectObject(dc,old);DeleteObject(f);f=make_font(12);old=(HFONT)SelectObject(dc,f);SetTextColor(dc,kColors.muted);DrawTextW(dc,L"Original audio is NOT ducked in Overlay mode.",-1,&(RECT{40,404,r.right-40,424}),DT_LEFT|DT_SINGLELINE);SelectObject(dc,old);DeleteObject(f);EndPaint(hwnd_,&ps);}
    LRESULT command(WPARAM w){int id=LOWORD(w);if(id==IDC_START&&HIWORD(w)==BN_CLICKED){active_?stop():start();return 0;}if(id==IDC_SAVE&&HIWORD(w)==BN_CLICKED){save_key();return 0;}if(id==IDC_FORGET&&HIWORD(w)==BN_CLICKED){forget_key();return 0;}if(id==IDC_CLOSE&&HIWORD(w)==BN_CLICKED){SendMessageW(hwnd_,WM_CLOSE,0,0);return 0;}if(id==IDC_SHOW_KEY&&HIWORD(w)==BN_CLICKED){bool show=SendMessageW(show_,BM_GETCHECK,0,0)==BST_CHECKED;SendMessageW(key_,EM_SETPASSWORDCHAR,show?0:L'•',0);InvalidateRect(key_,nullptr,TRUE);return 0;}return 0;}
    void post(const std::string&s,bool good=true){auto*m=new StatusMessage{wide_from_utf8(s),good};PostMessageW(hwnd_,WM_APP_STATUS,0,(LPARAM)m);}
    void set_status(const std::wstring&s,bool good){SetWindowTextW(status_,s.c_str());SetWindowTextW(gem_,s.c_str());if(!good)SetWindowTextW(out_,L"No translated audio");InvalidateRect(hwnd_,nullptr,FALSE);}
    std::string read_key()const{int n=GetWindowTextLengthW(key_);std::wstring s((size_t)n,L'\0');if(n)GetWindowTextW(key_,s.data(),n+1);return utf8_from_wide(s);}
    std::string lang()const{int i=(int)SendMessageW(lang_,CB_GETCURSEL,0,0);return i>=0&&i<(int)kLangs.size()?kLangs[(size_t)i].code:"fa";}
    void save_key(){auto k=read_key();if(k.empty()){set_status(L"Enter a Gemini API key first",false);SetFocus(key_);return;}set_status(save_secret(k)?L"API key saved securely":L"Could not save the API key",true);}
    void forget_key(){if(active_){set_status(L"Stop translation before forgetting the key",false);return;}if(forget_secret()){SetWindowTextW(key_,L"");set_status(L"Saved API key removed",true);}else set_status(L"Could not remove saved API key",false);}
    void start(){auto k=read_key();if(k.empty()){set_status(L"Enter your Gemini API key to start",false);SetFocus(key_);return;}active_=true;SetWindowTextW(start_,L"Stop translation");EnableWindow(key_,FALSE);EnableWindow(show_,FALSE);EnableWindow(lang_,FALSE);EnableWindow(save_,FALSE);EnableWindow(forget_,FALSE);aq_=std::make_unique<AudioQueue>();render_=std::make_unique<WasapiRender>([this](const std::string&s){post(s,true);});cap_=std::make_unique<WasapiLoopback>(*aq_,[this](const std::string&s){post(s,true);});gemini_=std::make_unique<GeminiLiveClient>(*aq_,k,lang(),[this](const std::vector<std::int16_t>&pcm){if(render_)render_->push(pcm);},[this](const std::string&s,bool good){post(s,good);});set_status(L"Starting capture and Gemini…",true);SetWindowTextW(src_,L"Starting system playback capture…");SetWindowTextW(out_,L"Waiting for Gemini audio…");render_->start();cap_->start();gemini_->start();}
    void stop(){active_=false;if(cap_)cap_->stop();if(aq_)aq_->stop();if(gemini_)gemini_->stop();if(render_)render_->stop();cap_.reset();gemini_.reset();render_.reset();aq_.reset();EnableWindow(key_,TRUE);EnableWindow(show_,TRUE);EnableWindow(lang_,TRUE);EnableWindow(save_,TRUE);EnableWindow(forget_,TRUE);SetWindowTextW(start_,L"Start translation");SetWindowTextW(src_,L"Waiting for system playback");SetWindowTextW(gem_,L"Disconnected");SetWindowTextW(out_,L"Waiting for translated audio");SetWindowTextW(status_,L"Stopped · ready to start again");}
    void shutdown(){if(active_)stop();}
};

} // namespace

int APIENTRY wWinMain(HINSTANCE hInst,HINSTANCE,LPWSTR,int){App app;return app.run(hInst);}
