#pragma once

#include <string>     // Telesa zahtev in odgovorov ter nastavitve strežnika.
#include <memory>     // Pametni kazalec na skrito implementacijo.
#include <thread>     // Nit, v kateri strežnik sprejema povezave.
#include <map>        // Podatki poizvedbenih parametrov URL-ja.
#include <functional> // Povratne funkcije, ki REST poti povežejo z aplikacijo.
#include <vector>     // Seznam povezanih WebSocket odjemalcev.
#include <cstdint>    // Števci in časovne vrednosti metrik.

/**
 * @class RestAPIServer
 * @brief HTTP REST API strežnik za nadzor in spremljanje IDS.
 *
 * Poti HTTP:
 * - GET  /api/status        - stanje IDS in metrike
 * - GET  /api/config        - trenutna konfiguracija
 * - POST /api/config        - posodobitev konfiguracije
 * - GET  /api/alerts        - zadnja opozorila
 * - GET  /api/metrics       - meritve delovanja
 * - WS   /ws                - sprotni dogodki prek WebSocket
 */
// Poveže HTTP poti z aplikacijskimi povratnimi funkcijami in oddaja dogodke.
class RestAPIServer {
public:
    // Naslov in vrata HTTP strežnika ter nastavitve njegovega delovanja.
    struct Config {
        std::string host = "0.0.0.0";
        int port = 8080;
        std::string log_level = "INFO";
        int num_threads = 4;
    };

    // Metrike, ki jih aplikacija posreduje poti /api/status.
    struct SystemMetrics {
        uint64_t total_packets = 0;
        uint64_t active_flows = 0;
        uint64_t alerts = 0;
        uint64_t anomalies = 0;
        uint64_t anomalies_detected = 0;
        float packets_per_sec = 0.0f;
        float cpu_usage_percent = 0.0f;
        float memory_usage_mb = 0.0f;
        uint64_t uptime_seconds = 0;
        std::string status = "running";
    };

    explicit RestAPIServer(const Config& config);
    ~RestAPIServer();

    // Inicializira strežnik in ga zažene v ločeni niti.
    bool initialize();

    // Povratne funkcije, s katerimi main.cpp poda podatke REST potem.
    void set_status_provider(std::function<SystemMetrics()> provider);
    void set_config_getter(std::function<std::string()> getter);
    void set_config_setter(std::function<bool(const std::string&)> setter);
    void set_alerts_provider(std::function<std::string(int)> provider);
    void set_alerts_history_provider(std::function<std::string(int)> provider);
    void set_flows_provider(std::function<std::string(int)> provider);
    void set_statistics_provider(std::function<std::string()> provider);
    void set_alert_action_provider(std::function<bool(const std::string&, const std::string&)> provider);
    void set_shutdown_provider(std::function<void()> provider);

    // Pošlje dogodek vsem trenutno povezanim WebSocket odjemalcem.
    void broadcast_alert(const std::string& alert_json);
    void broadcast_event(const std::string& event_type, const std::string& data_json);

    // Zapre strežnik in počaka, da se njegova nit ustavi.
    void shutdown();

private:
    Config config_;
    std::unique_ptr<class RestAPIServerImpl> impl_;
    std::thread server_thread_;

    void server_loop();
};

/**
 * @class WebSocketManager
 * @brief Upravlja WebSocket povezave za sprotno pošiljanje podatkov.
 */
// Enostaven pomožni razred; dejanske povezave /ws upravlja RestAPIServerImpl.
class WebSocketManager {
public:
    WebSocketManager(int port);
    ~WebSocketManager();

    bool initialize();
    void broadcast_message(const std::string& message);
    void shutdown();

    struct ClientInfo {
        std::string id;
        std::string tenant_id;
    };

private:
    int port_;
    std::vector<ClientInfo> connected_clients_;
    std::function<void(const std::string&)> on_message_callback_;
};
