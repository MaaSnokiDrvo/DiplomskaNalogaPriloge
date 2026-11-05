#ifndef IDS_FLOW_MANAGER_H
#define IDS_FLOW_MANAGER_H

#include "Common.h"       // Skupni podatkovni zapis Packet.
#include <unordered_map>  // Tabela aktivnih tokov po sestavljenem ključu.
#include <vector>         // Zbirke velikosti paketov in pripravljenih tokov.
#include <mutex>          // Zaščita skupne tabele tokov pred sočasnim dostopom.
#include <string>         // Naslovi, protokoli in ključi tokov.
#include <chrono>         // Časovni tipi pri upravljanju starosti tokov.

namespace ids {

// Časovni žig paketa in prag starosti toka sta oba izražena v mikrosekundah.
constexpr uint64_t MAX_FLOW_AGE_US = 5 * 60 * 1000000ULL;  // 5 minut

// Zbrane značilnosti in števci za pakete, ki pripadajo istemu toku.
struct FlowStats {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    std::vector<uint64_t> inter_arrival_times;
    std::vector<uint64_t> packet_sizes;
    uint64_t last_timestamp = 0;
    uint64_t creation_timestamp = 0;  // Čas zajema prvega paketa v toku.
    // Vrne urejen vektor osnovnih meritev toka za nadaljnjo obdelavo.
    std::vector<float> toFeatureVector() const;
}; // Zaključek definicije strukture.

class FlowManager {
public:
    // Doda veljaven paket v pripadajoči tok in posodobi njegove števce.
    void updateFlow(std::shared_ptr<Packet> packet);
    // Odstrani in vrne največ batch_size tokov, ki imajo vsaj pet paketov.
    std::vector<FlowStats> getReadyFlows(size_t batch_size);

    // Odstrani tokove, ki presegajo nastavljeno starost.
    void cleanupExpiredFlows(uint64_t current_timestamp);

    // Vrne število trenutno aktivnih tokov.
    size_t getActiveFlowsCount() const {
        std::lock_guard lock(flow_mutex);
        return active_flows.size();
    }

private:
    std::unordered_map<std::string, FlowStats> active_flows;
    mutable std::mutex flow_mutex;
    uint64_t last_cleanup_timestamp_ = 0;
    std::string generateKey(std::shared_ptr<Packet> packet);
    void cleanupExpiredFlowsLocked(uint64_t current_timestamp);
}; // Zaključek definicije razreda.

} // namespace ids

#endif
