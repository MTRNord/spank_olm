#pragma once
#include <array>
#include <botan/rng.h>

/**
 * number of bytes in each part of the ratchet; this should be the same as
 * the length of the hash function used in the HMAC (32 bytes for us, as we
 * use HMAC-SHA-256)
 */
#define MEGOLM_RATCHET_PART_LENGTH 32 /* SHA256_OUTPUT_LENGTH */

/**
 * number of parts in the ratchet; the advance() implementations rely on
 * this being 4.
 */
#define MEGOLM_RATCHET_PARTS 4

#define MEGOLM_RATCHET_LENGTH (MEGOLM_RATCHET_PARTS * MEGOLM_RATCHET_PART_LENGTH)

namespace spank_olm
{
    struct Megolm
    {
        std::array<std::array<std::uint8_t, MEGOLM_RATCHET_PART_LENGTH>, MEGOLM_RATCHET_PARTS> data;
        std::uint32_t counter;


        /**
         * \brief Initialize the megolm ratchet.
         */
        void init(Botan::RandomNumberGenerator &rng, unsigned int counter);

        /**
         * \brief Returns the number of bytes needed to store a megolm
         */
        [[nodiscard]] size_t pickle_length() const;

        /**
         * \brief Pickle the megolm.
         */
        std::uint8_t *pickle(std::uint8_t *pos) const;

        /**
         * \brief Unpickle the megolm.
         */
        std::uint8_t const *unpickle(std::uint8_t const *pos, const std::uint8_t *end);

        /**
         * \brief Advance the megolm ratchet by one step.
         */
        void advance();

        /**
         * \brief Advance the megolm ratchet by a given number of steps.
         */
        void advance(unsigned int advance_to);

        [[nodiscard]] const uint8_t *get_data() const { return reinterpret_cast<const uint8_t *>(data.data()); }
    };
} // namespace spank_olm
