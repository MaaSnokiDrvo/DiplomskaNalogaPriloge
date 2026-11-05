#include "Analytics.h" // Vmesnik za statistične izračune.
#include <numeric>     // Kopičenje vrednosti pri izračunu povprečja.
#include <algorithm>   // Standardni algoritmi za delo z zbirkami.
#include <cmath>       // Logaritem in kvadratni koren.

namespace ids {

double Analytics::calculateStdDev(const std::vector<uint64_t>& values) {
    if (values.empty()) return 0.0;

    // Izračunamo povprečje in nato povprečje kvadratov odklonov od njega.
    double sum = 0.0;
    for (uint64_t v : values) sum += static_cast<double>(v);

    double mean = sum / values.size();

    double sq_sum = 0.0;
    for (uint64_t v : values) {
        double val = static_cast<double>(v);
        sq_sum += (val - mean) * (val - mean);
    }

    return std::sqrt(sq_sum / values.size());
}

}
