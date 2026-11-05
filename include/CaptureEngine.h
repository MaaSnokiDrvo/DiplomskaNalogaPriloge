#ifndef IDS_CAPTURE_ENGINE_H
#define IDS_CAPTURE_ENGINE_H

#include "Common.h" // Skupna struktura Packet, ki jo zajem vrne klicatelju.
#include <memory>   // unique_ptr za skrito implementacijo in shared_ptr za pakete.
#include <string>   // Ime omrežne naprave, izbrane za zajem.

namespace ids {

// Skrbi za odpiranje naprave, zajem paketov v niti in njihovo predajo programu.
class CaptureEngine {
public:
    CaptureEngine();
    ~CaptureEngine();

    // Odpre izbrano napravo za zajem; ob neuspehu vrne false.
    bool init(const std::string& device_name);
    // Zažene zajem v delovni niti.
    void run();
    // Ustavi zajem in počaka, da se delovna nit zaključi.
    void stop();

    // Vrne naslednji paket iz čakalne vrste ali nullptr, če v njej še ni paketa.
    std::shared_ptr<Packet> dequeuePacket();

private:
    // Skrije podrobnosti zajema, da niso del javnega vmesnika.
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace ids

#endif
