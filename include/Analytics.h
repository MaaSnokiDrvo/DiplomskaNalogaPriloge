#ifndef IDS_ANALYTICS_H
#define IDS_ANALYTICS_H

#include <vector>  // Vrednosti, za katere se računa statistika.
#include <cmath>   // Matematične funkcije, uporabljene pri statistiki.

namespace ids {

// Pomožni izračuni, uporabljeni pri opisu omrežnih tokov.
class Analytics {
public:
    /**
     * @brief Izračun standardnega odklona časovnih razmikov (IAT).
     */
    // Izračuna populacijski standardni odklon podanih meritev.
    static double calculateStdDev(const std::vector<uint64_t>& values);
};

} // namespace ids

#endif
