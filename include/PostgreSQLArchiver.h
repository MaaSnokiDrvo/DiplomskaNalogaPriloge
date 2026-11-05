#pragma once

#include <string>   // Besedilni podatki incidenta in nastavitve povezave.
#include <vector>   // Zapis incidentov, zbranih v enem paketu za vstavljanje.
#include <cstdint>  // Časovni žigi, vrata in številke protokolov.
#include <queue>    // Incidenti, ki čakajo na zapis v podatkovno bazo.
#include <thread>   // Ozadnja nit za paketno obdelavo vrste.
#include <mutex>    // Varuje dostop do vrste čakajočih incidentov.
#include <memory>   // Pametni kazalci v implementaciji povezave s podatkovno bazo.
#include "Common.h" // Skupni podatkovni tipi aplikacije.

/**
 * Arhivar za neobvezno shranjevanje incidentov.
 * Ob podpori libpq in nastavitvi POSTGRES_ENABLED=1 se incidenti shranijo v PostgreSQL.
 * Brez libpq ali dosegljive baze se arhiviranje ne izvede, demonstracija IDS pa se nadaljuje.
 */
class PostgreSQLArchiver {
public:
    // Nastavitve povezave in velikost paketa pri zapisu.
    struct Config {
        std::string host = "localhost";
        uint16_t port = 5432;
        std::string database = "netsentinel_db";
        std::string user = "netsentinel_user";
        std::string password = "nastavi_lokalno";
        bool enabled = true;
        size_t batch_size = 100;
    };

private:
    // Interni zapis enega incidenta, ki ga nit pozneje shrani v PostgreSQL.
    struct ArchiveRecord {
        uint64_t timestamp;
        std::string src_ip;
        uint16_t src_port;
        std::string dst_ip;
        uint16_t dst_port;
        uint8_t protocol;
        float anomaly_score;
        std::string incident_type;
        std::string severity;
        std::string description;
    };

    Config config_;

    // Največja velikost vrste; BATCH_TIMEOUT_MS trenutna delovna zanka še ne uporablja.
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    static constexpr uint64_t BATCH_TIMEOUT_MS = 5000;

    // Vrsta in stanje delovne niti; queue_mutex_ varuje samo dostop do vrste.
    std::queue<ArchiveRecord> batch_queue_;
    mutable std::mutex queue_mutex_;
    std::thread batch_thread_;
    bool running_ = false;

    // Števci uspešno in neuspešno obdelanih zapisov.
    uint64_t total_archived_ = 0;
    uint64_t failed_inserts_ = 0;
    uint64_t last_flush_time_ = 0;

    // Delovna nit pobira zapise iz vrste in jih posreduje v vstavljanje.
    void batchProcessorThread();

    // Zažene ozadnjo nit za paketno obdelavo; pokliče se med initialize().
    bool start();

    // Vstavi podani paket incidentov v PostgreSQL.
    bool insertBatch(const std::vector<ArchiveRecord>& records);

public:
    // Ustvari arhivar z izbranimi nastavitvami; povezavo odpre initialize().
    explicit PostgreSQLArchiver(const Config& config = Config());

    // Ob uničenju ustavi nit in poskusi shraniti še čakajoče zapise.
    ~PostgreSQLArchiver();

    // Preveri dosegljivost baze in zažene nit za arhiviranje.
    bool initialize();

    // Ustavi arhivar in počaka na konec niti; po želji pred tem izprazni vrsto.
    void stop(bool flush_remaining = true);

    // Zgradi zapis incidenta in ga doda v vrsto; zapis v bazo opravi delovna nit.
    bool archiveIncident(
        const std::string& src_ip,
        uint16_t src_port,
        const std::string& dst_ip,
        uint16_t dst_port,
        uint8_t protocol,
        float anomaly_score,
        const std::string& incident_type,
        const std::string& severity,
        const std::string& description
    );

    // Sinhrono poskusi shraniti vse trenutno čakajoče zapise.
    bool flush();

    // Vrne število zapisov v čakalni vrsti.
    size_t getPendingRecordCount() const;

    // Vrne skupno število uspešno arhiviranih zapisov.
    uint64_t getTotalArchived() const { return total_archived_; }

    // Vrne skupno število zapisov, ki jih ni bilo mogoče vstaviti.
    uint64_t getFailedInserts() const { return failed_inserts_; }

    // Preveri povezavo s podatkovno bazo in dostopnost zahtevane sheme.
    bool healthCheck() const;

    // Vrne trenutno konfiguracijo arhivarja.
    const Config& getConfig() const { return config_; }
};
