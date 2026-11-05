#include <algorithm>       // Pomozni algoritmi za izracun stevcev.
#include <atomic>          // Varni stevci in zastavice, ki jih uporablja vec niti.
#include <chrono>          // Merjenje casa delovanja in intervalov.
#include <csignal>         // Prestrezanje signala za urejeno zaustavitev.
#include <cstdint>         // Celo stevilo fiksne sirine za vrata in stevce.
#include <cstdlib>         // Branje spremenljivk okolja.
#include <ctime>           // Pretvorba casa in oznake dogodkov.
#include <deque>           // Omejen seznam zadnjih tokov in opozoril.
#include <filesystem>      // Ustvarjanje mape za izvoz podatkov.
#include <fstream>         // Zapis tokov v CSV datoteko.
#include <iomanip>         // Oblikovanje casovne oznake.
#include <iostream>        // Izpis stanja programa v terminal.
#include <mutex>           // Zascita skupnih podatkov med nitmi.
#include <nlohmann/json.hpp> // Pretvorba podatkov API-ja v JSON.
#include <sstream>         // Sestavljanje casovne oznake.
#include <string>          // Besedilne vrednosti in omrezni naslovi.
#include <thread>          // Sočasno izvajanje strežnika in simulatorja.
#include <vector>          // Zacasno shranjevanje pripravljenih tokov.

// Zajemalnik in upravljalnik omreznih tokov.
#include "CaptureEngine.h"
#include "FlowManager.h"
// API za GUI ter izbirno arhiviranje incidentov.
#include "RestAPIServer.h"
#include "PostgreSQLArchiver.h"

std::atomic<bool> keep_running(true);
std::atomic<uint64_t> next_flow_id(1);
void signal_handler(int signal) { if (signal == SIGINT) keep_running = false; }

using json = nlohmann::json;

// Zapisuje omrezni tok v obliki, ki jo uporabljajo API in simulator.
struct FlowRecord {
    std::string flow_id;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    double duration_sec = 0.0;
    double anomaly_score = 0.0;
};

// Vrne, ali naj se zajeti neoznaceni tokovi izvozijo kot benigni primeri.
static bool export_benign_enabled() {
    const char* env = std::getenv("NETSENTINEL_EXPORT_BENIGN");
    if (!env) {
        return true;
    }
    return std::string(env) != "0";
}

// Pot do izhodne CSV datoteke lahko nastavimo brez posega v kodo.
static std::string benign_export_path() {
    const char* env = std::getenv("NETSENTINEL_BENIGN_EXPORT_PATH");
    if (env && *env) {
        return std::string(env);
    }
    return "data/benign_flows.csv";
}

// Simulator je namenjen demonstraciji in je privzeto izklopljen.
static bool simulate_attacks_enabled() {
    const char* env = std::getenv("NETSENTINEL_SIMULATE_ATTACKS");
    if (!env) {
        return false;
    }
    return std::string(env) == "1";
}

// Doloci najmanjsi dovoljeni razmik med simuliranimi dogodki.
static int simulate_interval_ms() {
    const char* env = std::getenv("NETSENTINEL_SIMULATE_INTERVAL_MS");
    if (!env || !*env) {
        return 2000;
    }
    try {
        return std::max(250, std::stoi(env));
    } catch (...) {
        return 2000;
    }
}

static int benign_alert_interval_sec() {
    const char* env = std::getenv("NETSENTINEL_BENIGN_ALERT_INTERVAL_SEC");
    if (!env || !*env) {
        return 10;
    }
    try {
        return std::max(1, std::stoi(env));
    } catch (...) {
        return 10;
    }
}

// Prebere besedilno nastavitev ali vrne podano privzeto vrednost.
static std::string env_or_default(const char* name, const std::string& fallback) {
    const char* env = std::getenv(name);
    if (!env || !*env) {
        return fallback;
    }
    return std::string(env);
}

// Na Windowsu izbiro privzete naprave prepustimo zajemalniku.
static std::string default_capture_device() {
#ifdef _WIN32
    return "";
#else
    return "any";
#endif
}

// Prebere celo stevilo iz okolja in ga omeji na dovoljeno spodnjo mejo.
static int env_int_or_default(const char* name, int fallback, int min_value = 0) {
    const char* env = std::getenv(name);
    if (!env || !*env) {
        return fallback;
    }
    try {
        return std::max(min_value, std::stoi(env));
    } catch (...) {
        return fallback;
    }
}

// Podpira pogoste besedilne zapise za vklop in izklop nastavitve.
static bool env_bool_or_default(const char* name, bool fallback) {
    const char* env = std::getenv(name);
    if (!env || !*env) {
        return fallback;
    }
    const std::string value(env);
    return value == "1" || value == "true" || value == "TRUE" ||
           value == "yes" || value == "YES" || value == "on" || value == "ON";
}

// Ustvari casovno oznako UTC, ki se uporablja v API-ju in pri izvozu.
static std::string now_iso8601() {
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

// Doda tok v CSV in ob prvem zapisu ustvari tudi glavo stolpcev.
static void append_benign_csv(const std::string& path, const FlowRecord& record) {
    std::filesystem::path file_path(path);
    if (file_path.has_parent_path()) {
        std::filesystem::create_directories(file_path.parent_path());
    }

    const bool write_header = !std::filesystem::exists(file_path) || std::filesystem::file_size(file_path) == 0;
    std::ofstream file(file_path, std::ios::app);
    if (!file.is_open()) {
        return;
    }
    if (write_header) {
        file << "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_sent,bytes_recv,packets,duration_sec,anomaly_score,label\n";
    }
    const double half_bytes = static_cast<double>(record.bytes) / 2.0;
    file << now_iso8601() << ','
         << record.src_ip << ','
         << record.dst_ip << ','
         << record.src_port << ','
         << record.dst_port << ','
         << record.protocol << ','
         << half_bytes << ','
         << half_bytes << ','
         << record.packets << ','
         << record.duration_sec << ','
         << record.anomaly_score << ','
         << 0
         << '\n';
}

int main() {
    // Signal Ctrl+C uporabimo za urejeno zaustavitev vseh delov programa.
    std::signal(SIGINT, signal_handler);

    // Iz okolja preberemo omrezno napravo za zajem paketov.
    const std::string configured_interface = env_or_default("NETSENTINEL_INTERFACE", "");
    std::string device_guid = configured_interface;
    if (device_guid.empty() || device_guid == "Auto-detect" || device_guid == "Samodejno") {
        device_guid = env_or_default("NETSENTINEL_DEVICE_GUID", default_capture_device());
    }

    // Zajemalnik in upravljalnik pretvorita prejete pakete v omrezne tokove.
    ids::CaptureEngine capture;
    ids::FlowManager flow_manager;
    // REST API konfiguracija se lahko prilagodi brez spremembe izvorne kode.
    RestAPIServer::Config rest_config;
    rest_config.host = env_or_default("REST_API_HOST", "0.0.0.0");
    rest_config.port = env_int_or_default("REST_API_PORT", 8080, 1);
    rest_config.log_level = env_or_default("REST_API_LOG_LEVEL", "INFO");

    // Skupne stevce in zbirke bere API, zato so dostopi med nitmi usklajeni.
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_anomalies{0};
    auto start_time = std::chrono::steady_clock::now();
    auto last_metric_broadcast = std::chrono::steady_clock::now();
    std::mutex api_mutex;
    std::mutex export_mutex;
    std::atomic<bool> simulator_enabled{simulate_attacks_enabled()};
    std::atomic<int> simulator_interval{simulate_interval_ms()};
    const bool export_benign = export_benign_enabled();
    const std::string export_path = benign_export_path();
    const int benign_alert_interval = benign_alert_interval_sec();
    std::deque<FlowRecord> recent_flows;
    std::deque<json> recent_alerts;
    json config_json = {
        {"name", "NetSentinel-01"},
        {"threshold", 0.5},
        {"simulate_attacks", simulator_enabled.load()},
        {"simulate_interval_ms", simulator_interval.load()},
        {"benign_alert_interval_sec", benign_alert_interval},
        {"interface", device_guid.empty() ? "Auto-detect" : device_guid}
    };

    // PostgreSQL je izbiren; ob izklopu ali napaki se aplikacija nadaljuje.
    PostgreSQLArchiver::Config pg_config;
    pg_config.host = env_or_default("POSTGRES_HOST", "localhost");
    pg_config.port = static_cast<uint16_t>(
        env_int_or_default("POSTGRES_PORT", 5432, 1)
    );
    pg_config.user = env_or_default("POSTGRES_USER", "netsentinel_user");
    pg_config.password = env_or_default("POSTGRES_PASSWORD", "nastavi_lokalno");
    pg_config.database = env_or_default("POSTGRES_DB", "netsentinel_db");
    pg_config.enabled = env_bool_or_default("POSTGRES_ENABLED", false);

    PostgreSQLArchiver pg_archiver(pg_config);
    std::atomic<bool> postgres_archiver_ready{false};
    if (pg_config.enabled && pg_archiver.initialize()) {
        postgres_archiver_ready.store(true);
        std::cout << "[*] PostgreSQL archiver enabled: "
                  << pg_config.host << ":" << pg_config.port << "/"
                  << pg_config.database << std::endl;
    } else if (pg_config.enabled) {
        std::cerr << "[!] PostgreSQL archiver init failed (non-fatal, continuing without DB archival)" << std::endl;
    } else {
        std::cout << "[*] PostgreSQL archiver disabled (POSTGRES_ENABLED=0)" << std::endl;
    }

    // Ponudniki REST API-ja vrnejo stanje in podatke iz trenutnega procesa.
    RestAPIServer rest_server(rest_config);
    // Statusna koncna tocka vrne stevce, stevilo tokov in cas delovanja.
    rest_server.set_status_provider([&]() {
        RestAPIServer::SystemMetrics metrics;
        uint64_t recent_flow_count = 0;
        uint64_t recent_alert_count = 0;
        {
            std::lock_guard<std::mutex> lock(api_mutex);
            recent_flow_count = static_cast<uint64_t>(recent_flows.size());
            recent_alert_count = static_cast<uint64_t>(recent_alerts.size());
        }
        metrics.total_packets = total_packets.load();
        metrics.active_flows = simulator_enabled.load()
            ? recent_flow_count
            : std::max<uint64_t>(flow_manager.getActiveFlowsCount(), recent_flow_count);
        metrics.alerts = recent_alert_count;
        metrics.anomalies = total_anomalies.load();
        metrics.uptime_seconds = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_time
            ).count()
        );
        return metrics;
    });
    // Nastavitve se ob branju in spreminjanju zascitijo z zaklepom.
    rest_server.set_config_getter([&]() {
        std::lock_guard<std::mutex> lock(api_mutex);
        return config_json.dump();
    });
    // GUI lahko spremeni nastavitve simulatorja prek REST API-ja.
    rest_server.set_config_setter([&](const std::string& body) {
        try {
            auto incoming = json::parse(body);
            if (!incoming.is_object()) {
                return false;
            }
            bool new_simulator_enabled = simulator_enabled.load();
            int new_simulator_interval = simulator_interval.load();
            if (incoming.contains("simulate_attacks")) {
                try {
                    new_simulator_enabled = incoming.at("simulate_attacks").get<bool>();
                } catch (...) {
                    return false;
                }
            }
            if (incoming.contains("simulate_interval_ms")) {
                try {
                    new_simulator_interval = std::max(250, incoming.at("simulate_interval_ms").get<int>());
                } catch (...) {
                    return false;
                }
            }
            {
                std::lock_guard<std::mutex> lock(api_mutex);
                for (auto it = incoming.begin(); it != incoming.end(); ++it) {
                    config_json[it.key()] = it.value();
                }
                config_json["simulate_attacks"] = new_simulator_enabled;
                config_json["simulate_interval_ms"] = new_simulator_interval;
            }
            simulator_enabled.store(new_simulator_enabled);
            simulator_interval.store(new_simulator_interval);
            return true;
        } catch (...) {
            return false;
        }
    });
    // API vrne zadnje tokove in opozorila v obliki JSON.
    rest_server.set_flows_provider([&](int limit) {
        json out = json::array();
        std::lock_guard<std::mutex> lock(api_mutex);
        int count = 0;
        for (const auto& flow : recent_flows) {
            if (count++ >= limit) break;
            out.push_back({
                {"flow_id", flow.flow_id},
                {"src_ip", flow.src_ip},
                {"dst_ip", flow.dst_ip},
                {"src_port", flow.src_port},
                {"dst_port", flow.dst_port},
                {"protocol", flow.protocol},
                {"packets", flow.packets},
                {"bytes", flow.bytes},
                {"duration", flow.duration_sec},
                {"anomaly_score", flow.anomaly_score}
            });
        }
        return out.dump();
    });
    // Koncna tocka vrne omejeno stevilo zadnjih opozoril.
    rest_server.set_alerts_provider([&](int limit) {
        json out = json::array();
        std::lock_guard<std::mutex> lock(api_mutex);
        int count = 0;
        for (const auto& alert : recent_alerts) {
            if (count++ >= limit) break;
            out.push_back(alert);
        }
        return out.dump();
    });
    // Zgodovinski odgovor vrne trenutno shranjena opozorila.
    rest_server.set_alerts_history_provider([&](int) {
        json out = json::array();
        std::lock_guard<std::mutex> lock(api_mutex);
        for (const auto& alert : recent_alerts) {
            out.push_back(alert);
        }
        return out.dump();
    });
    // Statistika povzema stevce za nadzorno plosco.
    rest_server.set_statistics_provider([&]() {
        json stats;
        uint64_t recent_flow_count = 0;
        uint64_t recent_alert_count = 0;
        {
            std::lock_guard<std::mutex> lock(api_mutex);
            recent_flow_count = static_cast<uint64_t>(recent_flows.size());
            recent_alert_count = static_cast<uint64_t>(recent_alerts.size());
        }
        stats["total_packets"] = total_packets.load();
        stats["active_flows"] = simulator_enabled.load()
            ? recent_flow_count
            : std::max<uint64_t>(flow_manager.getActiveFlowsCount(), recent_flow_count);
        stats["alerts"] = recent_alert_count;
        stats["anomalies"] = total_anomalies.load();
        return stats.dump();
    });
    // Opozorilo lahko prek API-ja oznacimo kot potrjeno ali razreseno.
    rest_server.set_alert_action_provider([&](const std::string& alert_id, const std::string& action) {
        std::lock_guard<std::mutex> lock(api_mutex);
        for (auto& alert : recent_alerts) {
            try {
                if (alert.value("id", "") != alert_id) {
                    continue;
                }
                if (action == "acknowledge") {
                    alert["status"] = "ACKNOWLEDGED";
                } else if (action == "resolve") {
                    alert["status"] = "RESOLVED";
                } else {
                    return false;
                }
                alert["updated_at"] = now_iso8601();
                return true;
            } catch (...) {
                return false;
            }
        }
        return false;
    });
    rest_server.set_shutdown_provider([&]() {
        keep_running = false;
    });
    // Zazenemo HTTP/WebSocket strežnik, ki povezuje backend z GUI-jem.
    if (!rest_server.initialize()) {
        std::cerr << "[!] Failed to initialize REST API (non-fatal, continuing...)" << std::endl;
    }

    std::thread simulator_thread;
    simulator_thread = std::thread([&]() {
        int counter = 0;
        bool last_enabled_state = simulator_enabled.load();
        if (last_enabled_state) {
            std::cout << "[*] Attack simulator enabled (interval "
                      << simulator_interval.load() << " ms)" << std::endl;
        } else {
            std::cout << "[*] Attack simulator disabled at startup" << std::endl;
        }
        while (keep_running) {
            if (!simulator_enabled.load()) {
                if (last_enabled_state) {
                    std::cout << "[*] Attack simulator disabled via config" << std::endl;
                    last_enabled_state = false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }
            if (!last_enabled_state) {
                std::cout << "[*] Attack simulator enabled via config (interval "
                          << simulator_interval.load() << " ms)" << std::endl;
                last_enabled_state = true;
            }

                FlowRecord record;
                record.flow_id = "flow-" + std::to_string(next_flow_id.fetch_add(1));
                record.src_ip = "10.0.0." + std::to_string(10 + (counter % 50));
                record.dst_ip = "192.168.1.10";
                record.src_port = static_cast<uint16_t>(40000 + (counter % 2000));
                const uint16_t ports[] = {445, 3389, 139, 4444, 5555};
                record.dst_port = ports[counter % (sizeof(ports) / sizeof(ports[0]))];
                record.protocol = (counter % 2 == 0) ? "TCP" : "UDP";
                record.packets = 200 + (counter % 400);
                record.bytes = 50000 + (counter % 250000);
                record.duration_sec = 0.5 + (counter % 5);
                record.anomaly_score = 0.92;

                json alert;
                alert["id"] = "sim-" + std::to_string(counter) + "-" + std::to_string(std::time(nullptr));
                alert["timestamp"] = now_iso8601();
                alert["type"] = record.protocol;
                alert["severity"] = (counter % 3 == 0) ? "CRITICAL" : "HIGH";
                alert["status"] = "OPEN";
                alert["src_ip"] = record.src_ip;
                alert["dst_ip"] = record.dst_ip;
                alert["description"] = record.src_ip + ":" + std::to_string(record.src_port) +
                    " -> " + record.dst_ip + ":" + std::to_string(record.dst_port) +
                    ", paketi=" + std::to_string(record.packets) +
                    ", bajti=" + std::to_string(record.bytes);

                json flow_json;
                flow_json["flow_id"] = record.flow_id;
                flow_json["src_ip"] = record.src_ip;
                flow_json["dst_ip"] = record.dst_ip;
                flow_json["src_port"] = record.src_port;
                flow_json["dst_port"] = record.dst_port;
                flow_json["protocol"] = record.protocol;
                flow_json["packets"] = record.packets;
                flow_json["bytes"] = record.bytes;
                flow_json["duration"] = record.duration_sec;
                flow_json["anomaly_score"] = record.anomaly_score;
                flow_json["threat_id"] = alert["id"];
                flow_json["threat_level"] = alert["severity"];
                flow_json["threat_score"] = record.anomaly_score;
                flow_json["indicators"] = json::array({"simulated_attack"});
                flow_json["description"] = alert["description"];

                {
                    std::lock_guard<std::mutex> lock(api_mutex);
                    recent_flows.push_front(record);
                    if (recent_flows.size() > 200) {
                        recent_flows.pop_back();
                    }
                    recent_alerts.push_front(alert);
                    if (recent_alerts.size() > 200) {
                        recent_alerts.pop_back();
                    }
                    total_packets.fetch_add(record.packets);
                    total_anomalies++;
                }

                // V bazo vstavi le vsak peti simulirani napad, da omejiš količino podatkov.
                if (postgres_archiver_ready.load() && counter % 5 == 0) {
                    pg_archiver.archiveIncident(
                        record.src_ip,
                        record.src_port,
                        record.dst_ip,
                        record.dst_port,
                        (record.protocol == "TCP" ? 6 : 17), // 6=TCP, 17=UDP
                        static_cast<float>(record.anomaly_score),
                        "Simulated Attack",
                        (counter % 3 == 0) ? "CRITICAL" : "HIGH",
                        "Simulated malicious flow injected for demo."
                    );
                }

                rest_server.broadcast_event("flow", flow_json.dump());
                rest_server.broadcast_event("alert", alert.dump());
                rest_server.broadcast_event("threat", flow_json.dump());

                counter++;
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(simulator_interval.load())
                );
        }
    });

    // Ce zajem ni na voljo, lahko simulator vseeno omogoci demonstracijski zagon.
    const bool capture_ok = capture.init(device_guid);
    if (!capture_ok) {
        std::cerr << "[!] Napaka inicializacije kartice!" << std::endl;
        if (!simulator_enabled.load()) {
            return 1;
        }
        std::cout << "[*] Simulator-only mode active (capture disabled)." << std::endl;
    } else {
        capture.run();
    }
    std::cout << "[*] IDS tece. Vsaka pika pomeni prejet paket..." << std::endl;
    std::cout << "[*] REST API: http://" << rest_config.host << ":" << rest_config.port << "/api/status" << std::endl;

    int packet_count = 0;
    auto last_benign_alert = std::chrono::steady_clock::time_point{};
    // Glavna zanka prevzema pakete, posodablja tokove in obvesca GUI.
    while (keep_running) {
        if (!capture_ok) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        auto packet = capture.dequeuePacket();

        if (packet) {
            total_packets++;
            // Vsakih deset paketov izpisemo piko kot znak aktivnosti zajema.
            if (++packet_count % 10 == 0) std::cout << "." << std::flush;

            flow_manager.updateFlow(packet);

            // Pripravljene tokove prevzamemo v paketih po dva.
            auto batch = flow_manager.getReadyFlows(2);

            if (!batch.empty()) {
                std::cout << "\n[*] Paket dveh tokov je pripravljen..." << std::endl;
                std::vector<json> ws_flows;
                std::vector<FlowRecord> export_records;
                {
                    std::lock_guard<std::mutex> lock(api_mutex);
                    for (const auto& flow : batch) {
                        FlowRecord record;
                        record.flow_id = "flow-" + std::to_string(next_flow_id.fetch_add(1));
                        record.src_ip = flow.src_ip;
                        record.dst_ip = flow.dst_ip;
                        record.src_port = flow.src_port;
                        record.dst_port = flow.dst_port;
                        record.protocol = flow.protocol;
                        record.packets = flow.packet_count;
                        record.bytes = flow.byte_count;
                        record.duration_sec = (flow.last_timestamp > flow.creation_timestamp)
                            ? static_cast<double>(flow.last_timestamp - flow.creation_timestamp) / 1e6
                            : 0.0;
                        record.anomaly_score = 0.0;
                        recent_flows.push_front(record);
                        if (recent_flows.size() > 200) {
                            recent_flows.pop_back();
                        }
                        if (export_benign) {
                            export_records.push_back(record);
                        }
                        ws_flows.push_back({
                            {"flow_id", record.flow_id},
                            {"src_ip", record.src_ip},
                            {"dst_ip", record.dst_ip},
                            {"src_port", record.src_port},
                            {"dst_port", record.dst_port},
                            {"protocol", record.protocol},
                            {"packets", record.packets},
                            {"bytes", record.bytes},
                            {"duration", record.duration_sec},
                            {"anomaly_score", record.anomaly_score}
                        });
                    }
                }
                if (export_benign && !export_records.empty()) {
                    std::lock_guard<std::mutex> export_lock(export_mutex);
                    for (const auto& record : export_records) {
                        append_benign_csv(export_path, record);
                    }
                }
                for (const auto& flow_json : ws_flows) {
                    rest_server.broadcast_event("flow", flow_json.dump());
                }

                const auto now = std::chrono::steady_clock::now();
                if (now - last_benign_alert >= std::chrono::seconds(benign_alert_interval)) {
                    const auto& representative = ws_flows.front();
                    json benign_alert = {
                        {"id", "benign-" + std::to_string(packet_count) + "-" + std::to_string(std::time(nullptr))},
                        {"timestamp", now_iso8601()},
                        {"type", representative["protocol"]},
                        {"severity", "LOW"},
                        {"status", "RESOLVED"},
                        {"src_ip", representative["src_ip"]},
                        {"dst_ip", representative["dst_ip"]},
                        {"description",
                         representative["src_ip"].get<std::string>() + ":" +
                         std::to_string(representative["src_port"].get<int>()) + " -> " +
                         representative["dst_ip"].get<std::string>() + ":" +
                         std::to_string(representative["dst_port"].get<int>()) + ", paketi=" +
                         std::to_string(representative["packets"].get<int>()) + ", bajti=" +
                         std::to_string(representative["bytes"].get<int>())}
                    };
                    {
                        std::lock_guard<std::mutex> lock(api_mutex);
                        recent_alerts.push_front(benign_alert);
                        if (recent_alerts.size() > 200) {
                            recent_alerts.pop_back();
                        }
                    }
                    rest_server.broadcast_event("alert", benign_alert.dump());
                    last_benign_alert = now;
                }

                if (now - last_metric_broadcast >= std::chrono::seconds(1)) {
                    json metric;
                    metric["packets"] = total_packets.load();
                    metric["flows"] = flow_manager.getActiveFlowsCount();
                    metric["alerts"] = static_cast<uint64_t>(recent_alerts.size());
                    metric["anomalies"] = total_anomalies.load();
                    rest_server.broadcast_event("metric", metric.dump());
                    last_metric_broadcast = now;
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Ob zaustavitvi ustavimo zajem, zapremo API in pocakamo na simulator.
    std::cout << "\n[*] Gašenje IDS-a..." << std::endl;
    if (capture_ok) {
        capture.stop();
    }
    rest_server.shutdown();
    if (simulator_thread.joinable()) {
        simulator_thread.join();
    }

    std::cout << "[*] IDS zaustavljen. Statistika:" << std::endl;

    return 0;
}
