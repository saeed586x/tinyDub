#pragma once
#include <windows.h>
#include <string>

// Compatibility overload used by the current UI prototype when passing a
// std::wstring path to DeleteFileW. The Win32 API itself remains unchanged.
inline BOOL DeleteFileW(const std::wstring& path) noexcept {
    return ::DeleteFileW(path.c_str());
}
