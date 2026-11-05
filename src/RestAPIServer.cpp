#include "RestAPIServer.h"          // Javni vmesnik in tipi REST strežnika.
#include <nlohmann/json.hpp>        // Pretvorba podatkov in sporočil v JSON.
#include <boost/asio.hpp>           // Omrežni vhodno-izhodni kontekst in naslovi.
#include <boost/asio/thread_pool.hpp> // Omejen bazen delovnih niti.
#include <boost/asio/ip/tcp.hpp>    // TCP vtičnice in končne točke.
#include <boost/beast.hpp>          // HTTP sporočila ter branje in pisanje.
#include <boost/beast/websocket.hpp> // Nadgradnja HTTP povezave v WebSocket.
#include <iostream>                 // Diagnostični izpisi ob zagonu strežnika.
#include <sstream>                  // Razčlenjevanje URL-ja in oblikovanje časa.
#include <chrono>                   // Časovni žigi dogodkov.
#include <iomanip>                  // Oblikovanje časovnega žiga ISO 8601.
#include <mutex>                    // Varuje zbirko sej WebSocket.
#include <vector>                   // Zbirka aktivnih WebSocket sej.
#include <atomic>                   // Stanje sprejemne zanke.
#include <map>                      // Parametri poizvedbenega niza.
#include <memory>                   // Skupno lastništvo WebSocket sej.
#include <algorithm>                // Omejitev števila delovnih niti.
#include <condition_variable>       // Čakanje oddajne niti na dogodke.
#include <queue>                    // Omejena vrsta WebSocket dogodkov.

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Predstavlja eno WebSocket povezavo in serializira zapise v vtičnico.
class WebSocketSession {
public:
    explicit WebSocketSession(tcp::socket socket)
        : ws_(std::move(socket)) {}

    bool accept(http::request<http::string_body>& req) {
        // Nadgradi že prebrano HTTP zahtevo v WebSocket sejo.
        beast::error_code ec;
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(http::field::server, "NetSentinel-IDS");
        }));
        ws_.accept(req, ec);
        open_ = !ec;
        return open_;
    }

    bool is_open() const {
        return open_;
    }

    bool send_text(const std::string& message) {
        // Samo ena nit sme hkrati zapisovati v isto WebSocket povezavo.
        if (!open_) {
            return false;
        }
        std::lock_guard<std::mutex> lock(write_mutex_);
        beast::error_code ec;
        ws_.text(true);
        ws_.write(net::buffer(message), ec);
        if (ec) {
            open_ = false;
        }
        return !ec;
    }

    void close() {
        if (!open_) {
            return;
        }
        beast::error_code ec;
        ws_.close(websocket::close_code::normal, ec);
        open_ = false;
    }

private:
    websocket::stream<tcp::socket> ws_;
    std::mutex write_mutex_;
    std::atomic<bool> open_{false};
};

class RestAPIServerImpl {
public:
    explicit RestAPIServerImpl(const RestAPIServer::Config& config)
        : config_(config),
          running_(false),
          ioc_(1),
          acceptor_(ioc_),
          worker_pool_(static_cast<unsigned int>(std::max(1, config.num_threads))) {}

    bool initialize() {
        // Pripravi TCP sprejemnik, ga poveže na naslov in začne poslušati.
        boost::system::error_code ec;
        auto address = net::ip::make_address(config_.host, ec);
        if (ec) {
            address = net::ip::make_address("0.0.0.0", ec);
        }
        tcp::endpoint endpoint{address, static_cast<unsigned short>(config_.port)};

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            return false;
        }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        acceptor_.bind(endpoint, ec);
        if (ec) {
            return false;
        }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            return false;
        }

        std::cout << "[RestAPIServer] Initialized on " << config_.host
                  << ":" << config_.port << std::endl;
        return true;
    }

    void set_status_provider(std::function<RestAPIServer::SystemMetrics()> provider) {
        status_provider_ = provider;
    }

    void set_config_getter(std::function<std::string()> getter) {
        config_getter_ = getter;
    }

    void set_config_setter(std::function<bool(const std::string&)> setter) {
        config_setter_ = setter;
    }

    void set_alerts_provider(std::function<std::string(int)> provider) {
        alerts_provider_ = provider;
    }

    void set_alerts_history_provider(std::function<std::string(int)> provider) {
        alerts_history_provider_ = provider;
    }

    void set_flows_provider(std::function<std::string(int)> provider) {
        flows_provider_ = provider;
    }

    void set_statistics_provider(std::function<std::string()> provider) {
        statistics_provider_ = provider;
    }

    void set_alert_action_provider(std::function<bool(const std::string&, const std::string&)> provider) {
        alert_action_provider_ = provider;
    }

    void set_shutdown_provider(std::function<void()> provider) {
        shutdown_provider_ = provider;
    }

    bool start() {
        // Sinhrona sprejemna zanka obdeluje povezave eno za drugo v strežniški niti.
        running_ = true;
        broadcast_thread_ = std::thread(&RestAPIServerImpl::broadcast_loop, this);
        while (running_) {
            boost::system::error_code ec;
            tcp::socket socket(ioc_);
            acceptor_.accept(socket, ec);
            if (ec) {
                if (!running_) {
                    break;
                }
                continue;
            }
            net::post(worker_pool_, [this, socket = std::move(socket)]() mutable {
                handle_connection(std::move(socket));
            });
        }
        return true;
    }

    void stop() {
        // Zapre sprejemnik in vse aktivne seje, da se strežniška nit lahko konča.
        running_ = false;
        boost::system::error_code ec;
        acceptor_.close(ec);
        ioc_.stop();
        broadcast_cv_.notify_all();

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            for (auto& session : sessions_) {
                if (session) {
                    session->close();
                }
            }
            sessions_.clear();
        }
        worker_pool_.join();
        if (broadcast_thread_.joinable()) {
            broadcast_thread_.join();
        }
    }

    void broadcast_event(const std::string& event_type, const std::string& data_json) {
        // Dogodek normaliziramo v ovojnico {type, data} in jo pošljemo vsem sejam.
        json data;
        try {
            data = json::parse(data_json);
        } catch (...) {
            data = json::object();
        }

        if (!data.is_object()) {
            json wrapper;
            wrapper["value"] = data;
            data = wrapper;
        }

        if (!data.contains("timestamp")) {
            data["timestamp"] = now_iso8601();
        }

        json payload;
        payload["type"] = event_type;
        payload["data"] = data;

        const std::string message = payload.dump();
        {
            std::lock_guard<std::mutex> lock(broadcast_mutex_);
            if (broadcast_queue_.size() >= MAX_BROADCAST_QUEUE_SIZE) {
                broadcast_queue_.pop();
            }
            broadcast_queue_.push(message);
        }
        broadcast_cv_.notify_one();
    }

private:
    static constexpr size_t MAX_BROADCAST_QUEUE_SIZE = 1000;

    struct TargetParts {
        std::string path;
        std::map<std::string, std::string> query;
    };

    static TargetParts split_target(beast::string_view target) {
        // Loči pot od poizvedbenih parametrov, npr. /api/alerts?limit=10.
        TargetParts parts;
        std::string target_str(target);
        auto pos = target_str.find('?');
        parts.path = (pos == std::string::npos) ? target_str : target_str.substr(0, pos);
        if (pos == std::string::npos) {
            return parts;
        }

        std::string query_str = target_str.substr(pos + 1);
        std::stringstream ss(query_str);
        std::string item;
        while (std::getline(ss, item, '&')) {
            auto eq = item.find('=');
            if (eq == std::string::npos) {
                continue;
            }
            parts.query[item.substr(0, eq)] = item.substr(eq + 1);
        }
        return parts;
    }

    static int get_query_int(const TargetParts& parts, const std::string& key, int fallback) {
        // Neveljavna ali manjkajoča številska vrednost dobi privzeto vrednost.
        auto it = parts.query.find(key);
        if (it == parts.query.end()) {
            return fallback;
        }
        try {
            return std::stoi(it->second);
        } catch (...) {
            return fallback;
        }
    }

    static std::string now_iso8601() {
        // API dogodke označimo z UTC časom v standardnem zapisu ISO 8601.
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &time);
#else
        gmtime_r(&time, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    http::response<http::string_body> make_json_response(http::status status,
                                                         unsigned version,
                                                         const std::string& body) {
        // Enotno pripravi JSON odgovor, glavo Content-Type in dolžino telesa.
        http::response<http::string_body> res{status, version};
        res.set(http::field::content_type, "application/json");
        res.set(http::field::server, "NetSentinel-IDS");
        res.keep_alive(false);
        res.body() = body;
        res.prepare_payload();
        return res;
    }

    http::response<http::string_body> handle_http_request(const http::request<http::string_body>& req) {
        // Razvrsti zahtevo po HTTP metodi in poti ter pokliče ustrezni ponudnik podatkov.
        const auto parts = split_target(req.target());
        const std::string& path = parts.path;

        if (req.method() == http::verb::get && path == "/api/status") {
            json payload;
            try {
                if (status_provider_) {
                    auto metrics = status_provider_();
                    payload["packets"] = metrics.total_packets;
                    payload["flows"] = metrics.active_flows;
                    payload["alerts"] = metrics.alerts;
                    payload["anomalies"] = metrics.anomalies;
                    payload["packets_per_sec"] = metrics.packets_per_sec;
                    payload["cpu_usage_percent"] = metrics.cpu_usage_percent;
                    payload["memory_usage_mb"] = metrics.memory_usage_mb;
                    payload["uptime_seconds"] = metrics.uptime_seconds;
                    payload["status"] = metrics.status;
                }

                if (alerts_provider_) {
                    auto alerts_json = json::parse(alerts_provider_(5));
                    payload["recent_alerts"] = alerts_json;
                }
            } catch (...) {
                payload = json::object();
            }
            return make_json_response(http::status::ok, req.version(), payload.dump());
        }

        if (req.method() == http::verb::post && path == "/api/shutdown") {
            if (!shutdown_provider_) {
                return make_json_response(http::status::not_implemented, req.version(), "{}");
            }
            shutdown_provider_();
            return make_json_response(http::status::ok, req.version(), "{\"ok\":true}");
        }

        if (req.method() == http::verb::get && path == "/api/config") {
            if (config_getter_) {
                return make_json_response(http::status::ok, req.version(), config_getter_());
            }
            return make_json_response(http::status::ok, req.version(), "{}");
        }

        if (req.method() == http::verb::post && path == "/api/config") {
            if (!config_setter_) {
                return make_json_response(http::status::not_implemented, req.version(), "{}");
            }
            if (req.body().empty()) {
                return make_json_response(http::status::bad_request, req.version(), "{}");
            }
            bool ok = config_setter_(req.body());
            return make_json_response(ok ? http::status::ok : http::status::bad_request,
                                     req.version(),
                                     std::string("{\"ok\":") + (ok ? "true" : "false") + "}");
        }

        if (req.method() == http::verb::get && path == "/api/alerts") {
            int limit = get_query_int(parts, "limit", 100);
            json out;
            out["alerts"] = json::array();
            if (alerts_provider_) {
                try {
                    out["alerts"] = json::parse(alerts_provider_(limit));
                } catch (...) {
                    out["alerts"] = json::array();
                }
            }
            return make_json_response(http::status::ok, req.version(), out.dump());
        }

        if (req.method() == http::verb::get && path == "/api/alerts/history") {
            int days = get_query_int(parts, "days", 7);
            json out;
            out["history"] = json::array();
            if (alerts_history_provider_) {
                try {
                    out["history"] = json::parse(alerts_history_provider_(days));
                } catch (...) {
                    out["history"] = json::array();
                }
            }
            return make_json_response(http::status::ok, req.version(), out.dump());
        }

        const std::string alert_prefix = "/api/alerts/";
        if (req.method() == http::verb::post &&
            path.rfind(alert_prefix, 0) == 0) {
            auto action_start = path.find('/', alert_prefix.size());
            if (action_start != std::string::npos && action_start + 1 < path.size()) {
                if (!alert_action_provider_) {
                    return make_json_response(http::status::not_implemented, req.version(), "{}");
                }
                std::string alert_id = path.substr(alert_prefix.size(), action_start - alert_prefix.size());
                std::string action = path.substr(action_start + 1);
                if (alert_id.empty() || (action != "acknowledge" && action != "resolve")) {
                    return make_json_response(http::status::bad_request, req.version(), "{}");
                }
                bool ok = alert_action_provider_(alert_id, action);
                return make_json_response(ok ? http::status::ok : http::status::bad_request,
                                         req.version(),
                                         std::string("{\"ok\":") + (ok ? "true" : "false") + "}");
            }
        }

        if (req.method() == http::verb::get && path == "/api/flows") {
            int limit = get_query_int(parts, "limit", 50);
            json out;
            out["flows"] = json::array();
            if (flows_provider_) {
                try {
                    out["flows"] = json::parse(flows_provider_(limit));
                } catch (...) {
                    out["flows"] = json::array();
                }
            }
            return make_json_response(http::status::ok, req.version(), out.dump());
        }

        if (req.method() == http::verb::get && path == "/api/statistics") {
            if (statistics_provider_) {
                return make_json_response(http::status::ok, req.version(), statistics_provider_());
            }
            return make_json_response(http::status::ok, req.version(), "{}");
        }

        return make_json_response(http::status::not_found, req.version(), "{}");
    }

    void handle_connection(tcp::socket socket) {
        // Zahtevo preberemo enkrat; /ws preusmerimo v sejo, druge poti v HTTP usmerjevalnik.
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        boost::system::error_code ec;
        http::read(socket, buffer, req, ec);
        if (ec) {
            return;
        }

        if (websocket::is_upgrade(req) && req.target() == "/ws") {
            auto session = std::make_shared<WebSocketSession>(std::move(socket));
            if (session->accept(req)) {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                sessions_.push_back(session);
            }
            return;
        }

        auto res = handle_http_request(req);
        http::write(socket, res, ec);
        socket.shutdown(tcp::socket::shutdown_send, ec);
    }

    void broadcast_loop() {
        while (true) {
            std::string message;
            {
                std::unique_lock<std::mutex> lock(broadcast_mutex_);
                broadcast_cv_.wait(lock, [this] {
                    return !running_ || !broadcast_queue_.empty();
                });
                if (broadcast_queue_.empty()) {
                    if (!running_) {
                        break;
                    }
                    continue;
                }
                message = std::move(broadcast_queue_.front());
                broadcast_queue_.pop();
            }

            std::vector<std::shared_ptr<WebSocketSession>> sessions;
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                sessions = sessions_;
            }
            std::vector<std::shared_ptr<WebSocketSession>> active_sessions;
            active_sessions.reserve(sessions.size());
            for (const auto& session : sessions) {
                if (session && session->send_text(message)) {
                    active_sessions.push_back(session);
                }
            }
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                sessions_.swap(active_sessions);
            }
        }
    }

    RestAPIServer::Config config_;
    std::atomic<bool> running_;
    net::io_context ioc_;
    tcp::acceptor acceptor_;
    net::thread_pool worker_pool_;
    std::thread broadcast_thread_;

    std::function<RestAPIServer::SystemMetrics()> status_provider_;
    std::function<std::string()> config_getter_;
    std::function<bool(const std::string&)> config_setter_;
    std::function<std::string(int)> alerts_provider_;
    std::function<std::string(int)> alerts_history_provider_;
    std::function<std::string(int)> flows_provider_;
    std::function<std::string()> statistics_provider_;
    std::function<bool(const std::string&, const std::string&)> alert_action_provider_;
    std::function<void()> shutdown_provider_;

    std::mutex sessions_mutex_;
    std::vector<std::shared_ptr<WebSocketSession>> sessions_;
    std::mutex broadcast_mutex_;
    std::condition_variable broadcast_cv_;
    std::queue<std::string> broadcast_queue_;
};

// ============================================================================
// Izvedba javnega vmesnika RestAPIServer.
// ============================================================================

RestAPIServer::RestAPIServer(const Config& config)
    : config_(config),
      impl_(std::make_unique<RestAPIServerImpl>(config)) {}

RestAPIServer::~RestAPIServer() {
    shutdown();
}

bool RestAPIServer::initialize() {
    if (!impl_->initialize()) {
        return false;
    }

    server_thread_ = std::thread(&RestAPIServer::server_loop, this);
    return true;
}

void RestAPIServer::set_status_provider(std::function<SystemMetrics()> provider) {
    impl_->set_status_provider(provider);
}

void RestAPIServer::set_config_getter(std::function<std::string()> getter) {
    impl_->set_config_getter(getter);
}

void RestAPIServer::set_config_setter(std::function<bool(const std::string&)> setter) {
    impl_->set_config_setter(setter);
}

void RestAPIServer::set_alerts_provider(std::function<std::string(int)> provider) {
    impl_->set_alerts_provider(provider);
}

void RestAPIServer::set_alerts_history_provider(std::function<std::string(int)> provider) {
    impl_->set_alerts_history_provider(provider);
}

void RestAPIServer::set_flows_provider(std::function<std::string(int)> provider) {
    impl_->set_flows_provider(provider);
}

void RestAPIServer::set_statistics_provider(std::function<std::string()> provider) {
    impl_->set_statistics_provider(provider);
}

void RestAPIServer::set_alert_action_provider(std::function<bool(const std::string&, const std::string&)> provider) {
    impl_->set_alert_action_provider(provider);
}

void RestAPIServer::set_shutdown_provider(std::function<void()> provider) {
    impl_->set_shutdown_provider(provider);
}

void RestAPIServer::broadcast_alert(const std::string& alert_json) {
    impl_->broadcast_event("alert", alert_json);
}

void RestAPIServer::broadcast_event(const std::string& event_type, const std::string& data_json) {
    impl_->broadcast_event(event_type, data_json);
}

void RestAPIServer::shutdown() {
    impl_->stop();
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
}

void RestAPIServer::server_loop() {
    impl_->start();
}

// ============================================================================
// Izvedba pomožnega razreda WebSocketManager.
// ============================================================================

WebSocketManager::WebSocketManager(int port) : port_(port) {}

WebSocketManager::~WebSocketManager() {
    shutdown();
}

bool WebSocketManager::initialize() {
    std::cout << "[WebSocketManager] WebSocket server initialized on port " << port_ << std::endl;
    return true;
}

void WebSocketManager::broadcast_message(const std::string& message) {
    for (const auto& client : connected_clients_) {
        std::cout << "[WebSocketManager] Sending to client " << client.id << ": " << message << std::endl;
    }
}

void WebSocketManager::shutdown() {
    connected_clients_.clear();
}
