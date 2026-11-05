#ifndef IDS_PROTOCOL_PARSER_H
#define IDS_PROTOCOL_PARSER_H

#include "Common.h" // Struktura paketa, v katero se shranijo razčlenjeni podatki.
#include <cstdint>  // Bajtna polja in celoštevilska polja glav protokolov.
#include <memory>   // Deljeno lastništvo paketa med komponentami.

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h> // Omrežne pretvorbe in definicije za okolje Windows.
#endif

namespace ids {

// Minimalni zapis Ethernet glave, potreben za določitev vrste omrežne plasti.
struct IdsEthHeader {
    uint8_t  dhost[6];
    uint8_t  shost[6];
    uint16_t type;
};

// Zapis osnovnih polj IPv4 glave, ki jih uporablja razčlenjevalnik.
struct IdsIP4Header {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// Zapis IPv6 glave; trenutna metoda parse() IPv6 paketov še ne razčlenjuje.
struct IdsIP6Header {
    /// IPv6 glava (verzija 4 bita, traffic class 8 bitov, flow label 20 bitov)
    uint32_t version_traffic_flow;
    uint16_t payload_len;
    uint8_t  next_header;      // Protokol naslednje ravni (TCP=6, UDP=17, ICMPv6=58)
    uint8_t  hop_limit;        // TTL za IPv6
    uint8_t  saddr[16];        // IPv6 naslov vira (128 bitov)
    uint8_t  daddr[16];        // IPv6 naslov cilja (128 bitov)
};

// Zapis začetnih polj TCP glave, potrebnih za pridobitev vrat.
struct IdsTCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// Pretvori surove Ethernet bajte v osnovna polja IPv4, TCP ali UDP paketa.
class ProtocolParser {
public:
    /// Glavna metoda za razčlenjevanje paketov.
    // Vstopna točka; trenutno sprejme Ethernet/IPv4 in nato TCP ali UDP.
    static bool parse(std::shared_ptr<Packet> packet);

private:
    /// Razčlenjevanje IPv4 glave.
    static bool parseIPv4(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len);

    /// Rezervirana deklaracija; aktivna metoda parse() trenutno podpira IPv4.
    static bool parseIPv6(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len);

    /// Razčlenjevanje začetnih polj TCP glave.
    static bool parseTCP(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len);

    /// Razčlenjevanje začetnih polj UDP glave.
    static bool parseUDP(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len);

    /// Pomožna deklaracija za oblikovanje IPv6 naslova; v tej datoteki ni izvedena.
    static std::string formatIPv6(const uint8_t* addr);
};

} // namespace ids

#endif
