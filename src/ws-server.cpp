#include "ws-server.hpp"
#include "live-bridge.hpp" // for live::log_error / live::log_info

// Suppress MSVC warnings from library headers
#pragma warning(push, 0)
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#pragma warning(pop)

#include <mutex>
#include <unordered_map>
#include <atomic>

namespace ws {

using WsppServer = websocketpp::server<websocketpp::config::asio>;
using connection_hdl = websocketpp::connection_hdl;

// ---------------------------------------------------------------------------
// WsServer::Impl using websocketpp
// ---------------------------------------------------------------------------
struct WsServer::Impl {
    WsppServer server;
    std::thread server_thread;

    MessageCallback on_message;
    ConnectCallback on_connect;
    ConnectCallback on_disconnect;

    // Map connection handles to numeric client IDs
    std::mutex mtx;
    std::unordered_map<ClientId, connection_hdl> id_to_hdl;
    std::map<void*, ClientId> ptr_to_id;  // raw pointer -> id for reverse lookup
    std::atomic<uint64_t> next_id{1};

    ClientId register_connection(connection_hdl hdl) {
        ClientId cid = next_id.fetch_add(1);
        std::lock_guard<std::mutex> lk(mtx);
        id_to_hdl[cid] = hdl;
        ptr_to_id[hdl.lock().get()] = cid;
        return cid;
    }

    ClientId lookup_id(connection_hdl hdl) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = ptr_to_id.find(hdl.lock().get());
        if (it != ptr_to_id.end()) return it->second;
        return 0;
    }

    void remove_connection(connection_hdl hdl) {
        std::lock_guard<std::mutex> lk(mtx);
        auto ptr = hdl.lock().get();
        auto it = ptr_to_id.find(ptr);
        if (it != ptr_to_id.end()) {
            id_to_hdl.erase(it->second);
            ptr_to_id.erase(it);
        }
    }

    connection_hdl get_hdl(ClientId cid) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = id_to_hdl.find(cid);
        if (it != id_to_hdl.end()) return it->second;
        return connection_hdl(); // empty/expired
    }
};

// ---------------------------------------------------------------------------
// WsServer public API
// ---------------------------------------------------------------------------
WsServer::WsServer() : m_impl(std::make_unique<Impl>()) {}
WsServer::~WsServer() { stop(); }

bool WsServer::start(uint16_t port, MessageCallback on_message) {
    m_impl->on_message = std::move(on_message);

    try {
        auto& srv = m_impl->server;

        // Silence websocketpp logs (use our own logging)
        srv.clear_access_channels(websocketpp::log::alevel::all);
        srv.clear_error_channels(websocketpp::log::elevel::all);

        srv.init_asio();
        srv.set_reuse_addr(true);

        // Connection opened
        srv.set_open_handler([this](connection_hdl hdl) {
            ClientId cid = m_impl->register_connection(hdl);
            live::log_info("WS", "Client %llu connected", (unsigned long long)cid);
            if (m_impl->on_connect) m_impl->on_connect(cid);
        });

        // Connection closed
        srv.set_close_handler([this](connection_hdl hdl) {
            ClientId cid = m_impl->lookup_id(hdl);
            live::log_info("WS", "Client %llu disconnected", (unsigned long long)cid);
            m_impl->remove_connection(hdl);
            if (m_impl->on_disconnect) m_impl->on_disconnect(cid);
        });

        // Connection failed
        srv.set_fail_handler([this](connection_hdl hdl) {
            ClientId cid = m_impl->lookup_id(hdl);
            auto con = m_impl->server.get_con_from_hdl(hdl);
            live::log_error("WS", "Client %llu connection failed: %s",
                          (unsigned long long)cid,
                          con->get_ec().message().c_str());
            m_impl->remove_connection(hdl);
        });

        // Message received
        srv.set_message_handler([this](connection_hdl hdl, WsppServer::message_ptr msg) {
            if (!m_impl->on_message) return;
            ClientId cid = m_impl->lookup_id(hdl);
            if (cid == 0) return;
            m_impl->on_message(cid, msg->get_payload());
        });

        srv.listen(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port));
        srv.start_accept();

        // Run in background thread
        m_impl->server_thread = std::thread([this]() {
            try {
                m_impl->server.run();
            } catch (const std::exception& e) {
                live::log_error("WS", "Server thread exception: %s", e.what());
            } catch (...) {
                live::log_error("WS", "Server thread unknown exception!");
            }
        });

        return true;

    } catch (const std::exception& e) {
        live::log_error("WS", "Failed to start: %s", e.what());
        return false;
    }
}

void WsServer::set_on_connect(ConnectCallback cb) {
    m_impl->on_connect = std::move(cb);
}

void WsServer::set_on_disconnect(ConnectCallback cb) {
    m_impl->on_disconnect = std::move(cb);
}

void WsServer::send(ClientId client, const std::string& text) {
    try {
        auto hdl = m_impl->get_hdl(client);
        if (hdl.expired()) return;
        m_impl->server.send(hdl, text, websocketpp::frame::opcode::text);
    } catch (const std::exception& e) {
        live::log_error("WS", "Send to client %llu failed: %s",
                      (unsigned long long)client, e.what());
    }
}

void WsServer::broadcast(const std::string& text) {
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    for (auto& [cid, hdl] : m_impl->id_to_hdl) {
        try {
            m_impl->server.send(hdl, text, websocketpp::frame::opcode::text);
        } catch (...) {}
    }
}

void WsServer::stop() {
    if (!m_impl) return;
    try {
        m_impl->server.stop_listening();

        // Close all connections
        {
            std::lock_guard<std::mutex> lk(m_impl->mtx);
            for (auto& [cid, hdl] : m_impl->id_to_hdl) {
                try {
                    m_impl->server.close(hdl, websocketpp::close::status::going_away, "server shutdown");
                } catch (...) {}
            }
        }

        m_impl->server.stop();

        if (m_impl->server_thread.joinable())
            m_impl->server_thread.join();

    } catch (const std::exception& e) {
        live::log_error("WS", "Stop error: %s", e.what());
    }
}

int WsServer::client_count() const {
    std::lock_guard<std::mutex> lk(m_impl->mtx);
    return static_cast<int>(m_impl->id_to_hdl.size());
}

} // namespace ws
