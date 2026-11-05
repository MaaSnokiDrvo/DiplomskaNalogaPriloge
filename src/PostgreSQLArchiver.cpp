#include "PostgreSQLArchiver.h" // Vmesnik in podatkovni zapisi arhivarja.
#include "Log.h"               // Lahki makri za izpis stanja arhivarja.
#include <algorithm>            // Omejevanje velikosti paketov pri izpraznitvi vrste.
#include <chrono>               // Ustvarjanje časovnega žiga incidenta.
#include <ctime>                // Standardni časovni tipi.
#include <memory>               // RAII za samodejno sproščanje libpq virov.
#include <sstream>              // Sestavljanje niza s podatki za povezavo.

#ifdef HAVE_LIBPQ
#include <libpq-fe.h> // C-vmesnik knjižnice PostgreSQL libpq.
#endif

namespace {

#ifdef HAVE_LIBPQ
// Deleterja zagotovita, da se libpq povezava in rezultat sprostita tudi ob napaki.
struct PGConnDeleter {
    void operator()(PGconn* conn) const {
        if (conn) {
            PQfinish(conn);
        }
    }
};

struct PGResultDeleter {
    void operator()(PGresult* result) const {
        if (result) {
            PQclear(result);
        }
    }
};

using PGConnPtr = std::unique_ptr<PGconn, PGConnDeleter>;
using PGResultPtr = std::unique_ptr<PGresult, PGResultDeleter>;

std::string quoteConnInfoValue(const std::string& value) {
    // Ubežimo narekovaje in poševnice, da vrednost ostane en sam element conninfo.
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\\' || ch == '\'') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('\'');
    return out;
}

PGConnPtr connectDatabase(const PostgreSQLArchiver::Config& config) {
    // Povezavo odpremo z omejenim časom čakanja in takoj preverimo njeno stanje.
    std::ostringstream conninfo;
    conninfo << "host=" << quoteConnInfoValue(config.host)
             << " port=" << config.port
             << " dbname=" << quoteConnInfoValue(config.database)
             << " user=" << quoteConnInfoValue(config.user)
             << " password=" << quoteConnInfoValue(config.password)
             << " connect_timeout=3 application_name=netsentinel_ids";

    PGConnPtr conn(PQconnectdb(conninfo.str().c_str()));
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        const char* error = conn ? PQerrorMessage(conn.get()) : "allocation failed";
        LOG_ERROR("PostgreSQL", "Connection failed: %s", error);
        return nullptr;
    }

    return conn;
}

bool execCommand(PGconn* conn, const std::string& sql) {
    // Pomožna funkcija za ukaze brez rezultatskih vrstic, npr. BEGIN ali CREATE.
    PGResultPtr result(PQexec(conn, sql.c_str()));
    if (!result || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        const char* error = result ? PQresultErrorMessage(result.get()) : PQerrorMessage(conn);
        LOG_ERROR("PostgreSQL", "SQL command failed: %s", error);
        return false;
    }
    return true;
}

bool ensureIncidentSchema(PGconn* conn) {
    // Ob zagonu preverimo oziroma ustvarimo tabelo incidentov in uporabljene indekse.
    const std::string schema_sql = R"SQL(
        SET client_min_messages TO warning;
        CREATE TABLE IF NOT EXISTS incidents (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_ip INET,
            src_port INTEGER,
            dst_ip INET,
            dst_port INTEGER,
            protocol INTEGER,
            anomaly_score REAL,
            incident_type VARCHAR(80),
            severity VARCHAR(20),
            description TEXT,
            status VARCHAR(20) DEFAULT 'open',
            notes TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents (timestamp);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
        CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);
    )SQL";
    return execCommand(conn, schema_sql);
}
#endif

}  // namespace

PostgreSQLArchiver::PostgreSQLArchiver(const Config& config)
    : config_(config) {
    LOG_INFO("PostgreSQL Archiver", "Initialized with host=%s, port=%d, db=%s",
             config_.host.c_str(), config_.port, config_.database.c_str());
}

PostgreSQLArchiver::~PostgreSQLArchiver() {
    if (running_) {
        stop(true);
    }
}

bool PostgreSQLArchiver::initialize() {
    // Arhiviranje je izbirno; ob nedosegljivi bazi se lahko glavni demo nadaljuje.
    if (!config_.enabled) {
        LOG_WARN("PostgreSQL Archiver", "PostgreSQL archiver is disabled in config");
        return true;  // Izklop arhiviranja je namerna nastavitev, ne napaka inicializacije.
    }

    if (!healthCheck()) {
        LOG_WARN("PostgreSQL Archiver", "Database connection failed; DB archival is disabled");
        return false;
    }

    return start();
}

bool PostgreSQLArchiver::start() {
    // Zaženemo največ eno nit, ki bo v ozadju obdelovala čakajoče zapise.
    if (running_) {
        LOG_WARN("PostgreSQL Archiver", "Archiver already running");
        return false;
    }

    running_ = true;
    batch_thread_ = std::thread(&PostgreSQLArchiver::batchProcessorThread, this);
    return true;
}

void PostgreSQLArchiver::stop(bool flush_remaining) {
    // Po želji najprej izpraznimo čakalno vrsto, nato počakamo na konec niti.
    if (!running_) {
        return;
    }

    if (flush_remaining) {
        LOG_INFO("PostgreSQL Archiver", "Flushing %zu pending records...", batch_queue_.size());
        flush();
    }

    running_ = false;
    if (batch_thread_.joinable()) {
        batch_thread_.join();
    }
    LOG_INFO("PostgreSQL Archiver", "Batch processor thread stopped");
}

bool PostgreSQLArchiver::archiveIncident(
    const std::string& src_ip,
    uint16_t src_port,
    const std::string& dst_ip,
    uint16_t dst_port,
    uint8_t protocol,
    float anomaly_score,
    const std::string& incident_type,
    const std::string& severity,
    const std::string& description
) {
    // Tu incident samo validiramo in uvrstimo v vrsto; omrežni zapis je ločen.
    if (!running_) {
        LOG_WARN("PostgreSQL Archiver", "Archiver not running, cannot queue incident");
        return false;
    }

    ArchiveRecord record;
    record.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    record.src_ip = src_ip;
    record.src_port = src_port;
    record.dst_ip = dst_ip;
    record.dst_port = dst_port;
    record.protocol = protocol;
    record.anomaly_score = anomaly_score;
    record.incident_type = incident_type;
    record.severity = severity;
    record.description = description;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        if (batch_queue_.size() >= MAX_QUEUE_SIZE) {
            LOG_ERROR("PostgreSQL Archiver", "Queue full (%zu/%zu), dropping incident",
                     batch_queue_.size(), MAX_QUEUE_SIZE);
            failed_inserts_++;
            return false;
        }

        batch_queue_.push(record);
    }

    return true;
}

void PostgreSQLArchiver::batchProcessorThread() {
    // Delovna zanka pobira do batch_size zapisov in jih obdeluje zunaj zaklepa vrste.
    while (running_) {
        std::vector<ArchiveRecord> batch;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);

            // Iz vrste vzamemo največ toliko zapisov, kolikor jih določa batch_size.
            while (!batch_queue_.empty() && batch.size() < config_.batch_size) {
                batch.push_back(batch_queue_.front());
                batch_queue_.pop();
            }
        }

        // Vstavljanje opravimo zunaj zaklepa, da lahko druga nit medtem dodaja zapise.
        if (!batch.empty()) {
            if (insertBatch(batch)) {
                total_archived_ += batch.size();
            } else {
                failed_inserts_ += batch.size();
                LOG_ERROR("PostgreSQL Archiver", "Batch insertion failed: %zu records",
                         batch.size());
            }
        }

        // Kratek premor prepreči, da bi nit neprestano preverjala prazno vrsto.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool PostgreSQLArchiver::insertBatch(const std::vector<ArchiveRecord>& records) {
    // Brez podpore libpq se arhiviranje ne izvede; sicer celoten paket obdelamo v transakciji.
    if (records.empty()) {
        return true;
    }

#ifndef HAVE_LIBPQ
    LOG_ERROR("PostgreSQL Archiver", "libpq support was not compiled; cannot insert batch");
    return false;
#else
    auto conn = connectDatabase(config_);
    if (!conn) {
        return false;
    }
    if (!ensureIncidentSchema(conn.get())) {
        return false;
    }
    if (!execCommand(conn.get(), "BEGIN")) {
        return false;
    }

    // Vrednosti so podane ločeno od SQL-ukaza, zato se ne vstavljajo z lepljenjem nizov.
    const char* sql =
        "INSERT INTO incidents (timestamp, src_ip, src_port, dst_ip, dst_port, "
        "protocol, anomaly_score, incident_type, severity, description) "
        "VALUES (to_timestamp($1::double precision / 1000.0), $2::inet, $3::integer, "
        "$4::inet, $5::integer, $6::integer, $7::real, $8::varchar, $9::varchar, $10::text) "
        "ON CONFLICT DO NOTHING";

    for (const auto& rec : records) {
        const std::string timestamp = std::to_string(rec.timestamp);
        const std::string src_port = std::to_string(rec.src_port);
        const std::string dst_port = std::to_string(rec.dst_port);
        const std::string protocol = std::to_string(static_cast<int>(rec.protocol));
        const std::string anomaly_score = std::to_string(rec.anomaly_score);

        const char* values[] = {
            timestamp.c_str(),
            rec.src_ip.c_str(),
            src_port.c_str(),
            rec.dst_ip.c_str(),
            dst_port.c_str(),
            protocol.c_str(),
            anomaly_score.c_str(),
            rec.incident_type.c_str(),
            rec.severity.c_str(),
            rec.description.c_str()
        };

        PGResultPtr result(PQexecParams(
            conn.get(),
            sql,
            10,
            nullptr,
            values,
            nullptr,
            nullptr,
            0
        ));

        if (!result || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
            const char* error = result ? PQresultErrorMessage(result.get()) : PQerrorMessage(conn.get());
            LOG_ERROR("PostgreSQL Archiver", "Insert failed: %s", error);
            execCommand(conn.get(), "ROLLBACK");
            return false;
        }
    }

    if (!execCommand(conn.get(), "COMMIT")) {
        return false;
    }

    return true;
#endif
}

bool PostgreSQLArchiver::flush() {
    // Sinhrono izpraznimo vse čakajoče zapise v več paketih dovoljene velikosti.
    std::vector<ArchiveRecord> batch;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        while (!batch_queue_.empty()) {
            batch.push_back(batch_queue_.front());
            batch_queue_.pop();
        }
    }

    if (batch.empty()) {
        return true;
    }

    LOG_INFO("PostgreSQL Archiver", "Flushing %zu records", batch.size());

    // Večjo izpraznjeno vrsto razdelimo na manjše pakete velikosti batch_size.
    for (size_t i = 0; i < batch.size(); i += config_.batch_size) {
        auto end = std::min(i + config_.batch_size, batch.size());
        std::vector<ArchiveRecord> chunk(batch.begin() + i, batch.begin() + end);

        if (!insertBatch(chunk)) {
            failed_inserts_ += chunk.size();
            return false;
        }

        total_archived_ += chunk.size();
    }

    return true;
}

size_t PostgreSQLArchiver::getPendingRecordCount() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return batch_queue_.size();
}

bool PostgreSQLArchiver::healthCheck() const {
    // Preverimo povezavo, shemo in izvedbo preprostega poizvedbenega ukaza.
#ifndef HAVE_LIBPQ
    LOG_WARN("PostgreSQL Archiver", "Health check failed: libpq support was not compiled");
    return false;
#else
    auto conn = connectDatabase(config_);
    if (!conn) {
        LOG_ERROR("PostgreSQL Archiver", "Health check: FAILED");
        return false;
    }

    if (!ensureIncidentSchema(conn.get())) {
        LOG_ERROR("PostgreSQL Archiver", "Health check: schema verification failed");
        return false;
    }

    PGResultPtr result(PQexec(conn.get(), "SELECT 1"));
    const bool ok = result && PQresultStatus(result.get()) == PGRES_TUPLES_OK;
    if (ok) {
        LOG_INFO("PostgreSQL Archiver", "Health check: OK");
    } else {
        const char* error = result ? PQresultErrorMessage(result.get()) : PQerrorMessage(conn.get());
        LOG_ERROR("PostgreSQL Archiver", "Health check: FAILED (%s)", error);
    }
    return ok;
#endif
}
