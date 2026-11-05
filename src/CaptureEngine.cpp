#include "CaptureEngine.h" // Javni vmesnik zajema in skupni zapis Packet.
#include "ProtocolParser.h"

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h> // Windowsova definicija, ki lahko trči z imenom interface.
    #undef interface
    #include <iphlpapi.h>
    #include <netioapi.h>
#endif

#include <pcap.h>              // Libpcap/Npcap vmesnik za zajem paketov.
#include <iostream>            // Standardni izhod za diagnostična sporočila.
#include <thread>              // Ločena nit za blokirajočo zanko pcap_loop.
#include <atomic>              // Skupna zastavica stanja zajema.
#include <queue>               // Čakalna vrsta zajetih paketov.
#include <mutex>               // Varuje čakalno vrsto pred sočasnim dostopom.
#include <condition_variable>  // Obvesti porabnika, ko prispe nov paket.
#include <algorithm>
#include <cctype>

namespace ids {

#ifdef _WIN32
static std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

static bool contains_case_insensitive(const std::string& value, const std::string& needle) {
    return uppercase(value).find(uppercase(needle)) != std::string::npos;
}

static std::string adapter_guid(bool wireless) {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
        return {};
    }
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) != NO_ERROR) {
        return {};
    }

    std::string ethernet_guid;
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp || !adapter->AdapterName) {
            continue;
        }
        if (wireless && adapter->IfType == IF_TYPE_IEEE80211) {
            return adapter->AdapterName;
        }
        if (!wireless && ethernet_guid.empty() && adapter->IfType == IF_TYPE_ETHERNET_CSMACD) {
            ethernet_guid = adapter->AdapterName;
        }
    }
    return ethernet_guid;
}
#endif

// Skrita izvedba hrani ročaj pcap, delovno nit in vrsto zajetih paketov.
class CaptureEngine::Impl {
public:
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    pcap_t* handle = nullptr;
    std::atomic<bool> should_stop{false};
    std::thread worker_thread;
    std::queue<std::shared_ptr<Packet>> packet_queue;
    std::mutex queue_mutex;
    std::condition_variable cv;

    // Libpcap pokliče to funkcijo za vsak paket in nam preda njegove surove bajte.
    static void pcap_callback(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* raw_packet) {
        auto* impl = reinterpret_cast<Impl*>(user_data);

        auto packet = std::make_shared<Packet>();
        packet->buffer.assign(raw_packet, raw_packet + pkthdr->caplen);
        packet->length = pkthdr->len;
        // pcap poda sekunde in mikrosekunde; shranjena vrednost je zato v mikrosekundah.
        packet->timestamp = (uint64_t)pkthdr->ts.tv_sec * 1000000ULL + (uint64_t)pkthdr->ts.tv_usec;

        if (!ProtocolParser::parse(packet)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(impl->queue_mutex);
            if (impl->packet_queue.size() >= MAX_QUEUE_SIZE) {
                return;
            }
            impl->packet_queue.push(packet);
        }
        impl->cv.notify_one();
    }
};

// Konstruktor ustvari skrito implementacijo, ne da bi jo izpostavil v glavi.
CaptureEngine::CaptureEngine() : pImpl(std::make_unique<Impl>()) {}

CaptureEngine::~CaptureEngine() {
    stop();
}

bool CaptureEngine::init(const std::string& device_name) {
    // Odpiranje naprave je predpogoj za poznejši zagon zajema.
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string selected_device = device_name;
    pcap_if_t* devices = nullptr;
    pcap_if_t* selected = nullptr;

    if (selected_device.empty()) {
        if (pcap_findalldevs(&devices, errbuf) != 0 || !devices) {
            std::cerr << "[CaptureEngine] Npcap naprave niso na voljo: "
                      << errbuf << std::endl;
            return false;
        }
        std::string preferred_guid;
#ifdef _WIN32
        preferred_guid = uppercase(adapter_guid(true));
#endif
        for (auto* device = devices; device; device = device->next) {
            if (!preferred_guid.empty() && device->name &&
                uppercase(device->name).find(preferred_guid) != std::string::npos) {
                selected = device;
                break;
            }
        }
        for (auto* device = devices; !selected && device; device = device->next) {
            if ((device->flags & PCAP_IF_LOOPBACK) == 0) {
                selected = device;
                break;
            }
        }
        if (!selected) {
            selected = devices;
        }
        selected_device = selected->name ? selected->name : "";
    } else if (selected_device == "Auto-detect" || selected_device == "Samodejno") {
        selected_device.clear();
        return init(selected_device);
    } else if (selected_device == "eth0" || selected_device == "eth1" ||
               selected_device == "wlan0") {
        if (pcap_findalldevs(&devices, errbuf) != 0 || !devices) {
            std::cerr << "[CaptureEngine] Npcap naprave niso na voljo: "
                      << errbuf << std::endl;
            return false;
        }
        const std::string label = selected_device == "wlan0" ? "Wi-Fi" : "Ethernet";
#ifdef _WIN32
        const std::string preferred_guid = uppercase(adapter_guid(selected_device == "wlan0"));
#else
        const std::string preferred_guid;
#endif
        for (auto* device = devices; device; device = device->next) {
            if ((!preferred_guid.empty() && device->name &&
                 contains_case_insensitive(device->name, preferred_guid)) ||
                (device->description && contains_case_insensitive(device->description, label)) ||
                (device->name && contains_case_insensitive(device->name, selected_device))) {
                selected = device;
                break;
            }
        }
        if (!selected) {
            std::cerr << "[CaptureEngine] Vmesnika ni mogoče najti: "
                      << selected_device << std::endl;
            pcap_freealldevs(devices);
            return false;
        }
        selected_device = selected->name ? selected->name : "";
    }

    if (selected_device.empty()) {
        if (devices) {
            pcap_freealldevs(devices);
        }
        return false;
    }

    pImpl->handle = pcap_open_live(selected_device.c_str(), 65535, 1, 10, errbuf);
    if (devices) {
        pcap_freealldevs(devices);
    }

    if (!pImpl->handle) {
        std::cerr << "[CaptureEngine] Npcap naprave ni mogoče odpreti: "
                  << selected_device << " (" << errbuf << ")" << std::endl;
        return false;
    }
    std::cout << "[CaptureEngine] Zajemam na napravi: "
              << selected_device << std::endl;
    return true;
}

void CaptureEngine::run() {
    // pcap_loop teče v ozadju, da lahko glavni program sproti prevzema pakete.
    pImpl->should_stop = false;
    pImpl->worker_thread = std::thread([this]() {
        if (pImpl->handle) {
            pcap_loop(pImpl->handle, 0, Impl::pcap_callback, reinterpret_cast<u_char*>(pImpl.get()));
        }
    });
}

void CaptureEngine::stop() {
    // Prekinemo pcap zanko in počakamo na konec niti, preden se objekt uniči.
    pImpl->should_stop = true;
    if (pImpl->handle) {
        pcap_breakloop(pImpl->handle);
    }
    if (pImpl->worker_thread.joinable()) {
        pImpl->worker_thread.join();
    }
}

std::shared_ptr<Packet> CaptureEngine::dequeuePacket() {
    // Čakamo največ 50 ms; časovna omejitev omogoča tudi redno preverjanje izhoda.
    std::unique_lock<std::mutex> lock(pImpl->queue_mutex);
    if (pImpl->cv.wait_for(lock, std::chrono::milliseconds(50), [this] { return !pImpl->packet_queue.empty(); })) {
        auto packet = pImpl->packet_queue.front();
        pImpl->packet_queue.pop();
        return packet;
    }
    return nullptr;
}

} // namespace ids
