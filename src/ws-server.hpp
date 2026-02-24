#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <memory>

namespace ws {

using ClientId = uint64_t;
using MessageCallback = std::function<void(ClientId client, const std::string& message)>;
using ConnectCallback = std::function<void(ClientId client)>;

class WsServer {
public:
    WsServer();
    ~WsServer();

    bool start(uint16_t port, MessageCallback on_message);
    void set_on_connect(ConnectCallback cb);
    void set_on_disconnect(ConnectCallback cb);
    void send(ClientId client, const std::string& text);
    void broadcast(const std::string& text);
    void stop();
    int client_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ws
