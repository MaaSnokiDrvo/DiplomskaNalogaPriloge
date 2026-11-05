#include "ProtocolParser.h" // Glave protokolov in skupni zapis paketa.
#include <iostream>         // Standardni izhodni tokovi.

#ifdef _WIN32
    #include <winsock2.h> // Omrežne funkcije v okolju Windows.
    #include <ws2tcpip.h> // Pretvorba binarnih IP-naslovov v besedilo.
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <arpa/inet.h>  // Omrežne pretvorbe za Unixu podobne sisteme.
    #include <netinet/in.h> // Definicije internetnih naslovov in družin protokolov.
#endif

namespace ids {

bool ProtocolParser::parse(std::shared_ptr<Packet> packet) {
    if (!packet) return false;
    packet->is_valid = false;
    // Najprej preberemo Ethernet tip; nepodprte omrežne plasti zavrnemo.
    if (packet->buffer.size() < sizeof(IdsEthHeader)) return false;

    const auto* eth = reinterpret_cast<const IdsEthHeader*>(packet->buffer.data());
    packet->ether_type = ntohs(eth->type);

    if (packet->ether_type == 0x0800) { // IPv4
        return parseIPv4(packet, packet->buffer.data() + sizeof(IdsEthHeader),
                         packet->buffer.size() - sizeof(IdsEthHeader));
    }
    return false;
}

bool ProtocolParser::parseIPv4(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len) {
    // Iz IPv4 glave preberemo naslova in protokol, nato določimo položaj naslednje glave.
    if (len < sizeof(IdsIP4Header)) return false;

    const auto* ip = reinterpret_cast<const IdsIP4Header*>(buffer);

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    struct in_addr saddr, daddr;
    saddr.s_addr = ip->saddr;
    daddr.s_addr = ip->daddr;

    inet_ntop(AF_INET, &saddr, src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &daddr, dst_str, INET_ADDRSTRLEN);

    packet->src_ip = src_str;
    packet->dst_ip = dst_str;
    packet->ip_protocol = ip->protocol;

    size_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || len < ip_hdr_len) return false;

    const uint8_t* next_buf = buffer + ip_hdr_len;
    size_t next_len = len - ip_hdr_len;

    // Trenutna izvedba nadaljuje samo za TCP in UDP; druge protokole preskoči.
    if (packet->ip_protocol == 6) return parseTCP(packet, next_buf, next_len);
    if (packet->ip_protocol == 17) return parseUDP(packet, next_buf, next_len);

    return false;
}

bool ProtocolParser::parseTCP(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len) {
    // Preverimo dolžino glave in pretvorimo vrata iz omrežnega vrstnega reda bajtov.
    if (len < sizeof(IdsTCPHeader)) return false;
    const auto* tcp = reinterpret_cast<const IdsTCPHeader*>(buffer);
    packet->src_port = ntohs(tcp->source);
    packet->dst_port = ntohs(tcp->dest);
    const size_t tcp_hdr_len = static_cast<size_t>((ntohs(tcp->flags) >> 12) & 0x0F) * 4;
    if (tcp_hdr_len < sizeof(IdsTCPHeader) || len < tcp_hdr_len) return false;
    packet->payload.assign(buffer + tcp_hdr_len, buffer + len);
    packet->is_valid = true;
    return true;
}

bool ProtocolParser::parseUDP(std::shared_ptr<Packet> packet, const uint8_t* buffer, size_t len) {
    // Za UDP preberemo začetni polji vrat; preostanek vsebine tu ne razčlenjujemo.
    if (len < 8) return false;
    packet->src_port = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
    packet->dst_port = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    packet->payload.assign(buffer + 8, buffer + len);
    packet->is_valid = true;
    return true;
}

} // namespace ids
