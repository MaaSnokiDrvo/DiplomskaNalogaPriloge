#include "FlowManager.h" // Zapis toka ter vmesnik za upravljanje aktivnih tokov.
#include "Analytics.h"   // Izračun statistike vsebine in časovnih meritev.
#include <sstream>       // Sestavljanje ključa toka iz naslovov in vrat.
#include <numeric>       // Seštevanje časovnih razmikov.
#include <algorithm>     // Standardni algoritmi za obdelavo zbirk.
#include <iostream>      // Izpis ob odstranjevanju zastarelih tokov.

namespace ids {

// Pretvori številko IP-protokola v oznako, ki jo lažje beremo v izpisih.
static std::string protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return "OTHER";
    }
}

std::string FlowManager::generateKey(std::shared_ptr<Packet> packet) {
// Ključ vsebuje oba naslova in vrata; smer komunikacije je zato del ključa.
std::stringstream ss;
ss << packet->src_ip << ":" << packet->src_port << "->"
   << packet->dst_ip << ":" << packet->dst_port;
return ss.str();
}

void FlowManager::updateFlow(std::shared_ptr<Packet> packet) {
// Posodabljanje in čiščenje se izvajata pod istim zaklepom nad tabelo tokov.
if (!packet || !packet->is_valid) return;
std::lock_guard lock(flow_mutex);

auto key = generateKey(packet);
auto& stats = active_flows[key];

// Pri prvem paketu shranimo stalne podatke o končnih točkah in začetni čas.
if (stats.packet_count == 0) {
    stats.src_ip = packet->src_ip;
    stats.dst_ip = packet->dst_ip;
    stats.src_port = packet->src_port;
    stats.dst_port = packet->dst_port;
    stats.protocol = protocol_to_string(packet->ip_protocol);
    stats.creation_timestamp = packet->timestamp;  // NOVO
}

// Vsak naslednji paket razširi števce in meritve obstoječega toka.
stats.packet_count++;
stats.byte_count += packet->length;
stats.packet_sizes.push_back(packet->length);
if (stats.last_timestamp > 0 && packet->timestamp >= stats.last_timestamp) {
    stats.inter_arrival_times.push_back(packet->timestamp - stats.last_timestamp);
}
stats.last_timestamp = packet->timestamp;
if (last_cleanup_timestamp_ == 0 ||
    (packet->timestamp >= last_cleanup_timestamp_ &&
     packet->timestamp - last_cleanup_timestamp_ >= 1000000ULL)) {
    cleanupExpiredFlowsLocked(packet->timestamp);
    last_cleanup_timestamp_ = packet->timestamp;
}
}

std::vector<FlowStats> FlowManager::getReadyFlows(size_t batch_size) {
// Tok pošljemo naprej po najmanj petih paketih in ga odstranimo iz aktivne tabele.
std::lock_guard lock(flow_mutex);
std::vector<FlowStats> batch;
auto it = active_flows.begin();
while (it != active_flows.end() && batch.size() < batch_size) {
if (it->second.packet_count >= 5) {
batch.push_back(it->second);
it = active_flows.erase(it);
} else { ++it; }
}
return batch;
}

std::vector<float> FlowStats::toFeatureVector() const {
// Vektor ima stalen vrstni red: paketi, bajti, povprečje/odklon IAT,
// odklon velikosti paketov.
std::vector<float> vec;
vec.push_back((float)packet_count);
vec.push_back((float)byte_count);
float avg_iat = 0, std_iat = 0;
if (!inter_arrival_times.empty()) {
avg_iat = (float)std::accumulate(inter_arrival_times.begin(), inter_arrival_times.end(), 0ULL) / inter_arrival_times.size();
std_iat = (float)Analytics::calculateStdDev(inter_arrival_times);
}
vec.push_back(avg_iat);
vec.push_back(std_iat);
vec.push_back((float)Analytics::calculateStdDev(packet_sizes));
return vec;
}

void FlowManager::cleanupExpiredFlows(uint64_t current_timestamp) {
std::lock_guard lock(flow_mutex);
cleanupExpiredFlowsLocked(current_timestamp);
}

void FlowManager::cleanupExpiredFlowsLocked(uint64_t current_timestamp) {
// Odstranimo tokove, katerih čas od nastanka presega nastavljeno mejo.
// Starost primerjamo s pragom; updateFlow to funkcijo kliče z že zaklenjeno tabelo.
auto it = active_flows.begin();
while (it != active_flows.end()) {
    if (current_timestamp < it->second.creation_timestamp) {
        ++it;
        continue;
    }
    uint64_t flow_age = current_timestamp - it->second.creation_timestamp;
    if (flow_age > MAX_FLOW_AGE_US) {
        std::cout << "[*] Čišćenje isteknog toka: " << it->first << " (starost: "
                  << (flow_age / 1000000ULL) << "s)" << std::endl;
        it = active_flows.erase(it);
    } else {
        ++it;
    }
}
}

}
