#ifndef IDS_COMMON_H
#define IDS_COMMON_H

#include <vector>   // Zaporedja bajtov in podatkovnih elementov.
#include <cstdint>  // Celoštevilski tipi z določeno širino.
#include <memory>   // Pametni kazalci za skupno lastništvo paketov.
#include <string>   // Besedilni naslovi IP in druga besedilna polja.
#include <chrono>   // Časovni tipi standardne knjižnice.

namespace ids {

/**
 * @brief Osnovna struktura paketa za celoten cevovod.
 * Razširjeno iz prvotne verzije za podporo globoki analizi.
 */
// Skupni zapis paketa, ki ga uporabljajo zajem, razčlenjevalnik in obdelava tokov.
struct Packet {
    std::vector<uint8_t> buffer;       // Surovi podatki paketa
    uint64_t timestamp;                // Časovni žig zajema je trenutno izražen v mikrosekundah.
    uint32_t length;                   // Dejanska dolžina na žici

    // Polja, ki jih zapolni ProtocolParser
    uint16_t ether_type = 0;           // Ethernet tip (IPv4, IPv6...)
    uint8_t  ip_protocol = 0;          // TCP, UDP, ICMP
    std::string src_ip;                // Vir (string za lažje logiranje)
    std::string dst_ip;                // Cilj
    uint16_t src_port = 0;             // Izvorna vrata
    uint16_t dst_port = 0;             // Ciljna vrata

    bool is_valid = false;             // Ali je paket pravilno razčlenjen
    std::vector<uint8_t> payload;      // Le aplikacijski podatki za analizo
};

// Splošen zapis rezultata zaznavanja; sam zapis ne izvaja modela ali zaznavanja.
struct DetectionResult {
    std::string flow_id;
    double anomaly_score;
    std::string attack_type;
    bool is_threat;
};

} // namespace ids

#endif
