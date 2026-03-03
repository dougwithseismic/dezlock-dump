#include "src/version-check.hpp"
#include "version.h"
#include "vendor/json.hpp"

#include <Windows.h>
#include <winhttp.h>

#include <string>
#include <tuple>

#pragma comment(lib, "winhttp.lib")

// Parse "vMAJOR.MINOR.PATCH" into a tuple. Returns {0,0,0} on failure.
static std::tuple<int,int,int> parse_semver(const std::string& tag) {
    // Strip leading 'v' or 'V'
    size_t start = 0;
    if (!tag.empty() && (tag[0] == 'v' || tag[0] == 'V')) start = 1;

    int major = 0, minor = 0, patch = 0;
    if (sscanf(tag.c_str() + start, "%d.%d.%d", &major, &minor, &patch) < 2)
        return {0, 0, 0};
    return {major, minor, patch};
}

UpdateInfo check_for_update(int connect_timeout_ms) {
    UpdateInfo info;

    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    try {
        hSession = WinHttpOpen(
            L"dezlock-dump-update-check/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!hSession) return info;

        // Set timeouts: resolve, connect, send, receive
        WinHttpSetTimeouts(hSession,
            connect_timeout_ms,  // resolve
            connect_timeout_ms,  // connect
            connect_timeout_ms,  // send
            connect_timeout_ms); // receive

        hConnect = WinHttpConnect(hSession, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return info; }

        hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            L"/repos/dougwithseismic/dezlock-dump/releases/latest",
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return info;
        }

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return info;
        }

        if (!WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return info;
        }

        // Check HTTP status
        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
            WINHTTP_NO_HEADER_INDEX);
        if (status_code != 200) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return info;
        }

        // Read response body
        std::string body;
        DWORD bytes_available = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
            std::string chunk(bytes_available, '\0');
            DWORD bytes_read = 0;
            WinHttpReadData(hRequest, &chunk[0], bytes_available, &bytes_read);
            chunk.resize(bytes_read);
            body += chunk;

            // Safety limit: 64 KB should be more than enough for the release JSON
            if (body.size() > 65536) break;
        }

        WinHttpCloseHandle(hRequest);  hRequest = nullptr;
        WinHttpCloseHandle(hConnect);  hConnect = nullptr;
        WinHttpCloseHandle(hSession);  hSession = nullptr;

        // Parse JSON
        auto j = nlohmann::json::parse(body, nullptr, false);
        if (j.is_discarded() || !j.contains("tag_name"))
            return info;

        std::string latest_tag = j["tag_name"].get<std::string>();
        auto [lmaj, lmin, lpat] = parse_semver(latest_tag);
        auto [cmaj, cmin, cpat] = parse_semver(DEZLOCK_VERSION_STR);

        // Compare: latest > current?
        if (std::tie(lmaj, lmin, lpat) > std::tie(cmaj, cmin, cpat)) {
            info.has_update = true;
            info.latest_version = latest_tag;
            info.release_url = j.value("html_url",
                "https://github.com/dougwithseismic/dezlock-dump/releases/latest");
        }

    } catch (...) {
        // Any exception = silent failure
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    return info;
}
