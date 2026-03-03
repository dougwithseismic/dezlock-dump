#pragma once

#include <string>

struct UpdateInfo {
    bool has_update = false;
    std::string latest_version;
    std::string release_url;
};

// Check GitHub for a newer release. Returns silently on any failure.
// connect_timeout_ms controls how long to wait for the network (default 3s).
UpdateInfo check_for_update(int connect_timeout_ms = 3000);
