#include "megolm.hpp"
#include "pickle.hpp"

#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/mac.h>


/* Convenience macro for checking the return value of internal unpickling
 * functions and returning early on failure. */
#ifndef UNPICKLE_OK
#define UNPICKLE_OK(x)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(x))                                                                                                      \
            return nullptr;                                                                                            \
    }                                                                                                                  \
    while (0)
#endif

/* the seeds used in the HMAC-SHA-256 functions for each part of the ratchet.
 */
#define HASH_KEY_SEED_LENGTH 1
static uint8_t HASH_KEY_SEEDS[MEGOLM_RATCHET_PARTS][HASH_KEY_SEED_LENGTH] = {{0x00}, {0x01}, {0x02}, {0x03}};


namespace spank_olm
{
    constexpr size_t UINT32_LENGTH = 4;

    std::uint8_t *_olm_pickle_uint32(std::uint8_t *pos, uint32_t const value) { return pickle(pos, value); }


    std::uint8_t const *_olm_unpickle_uint32(std::uint8_t const *pos, std::uint8_t const *end, std::uint32_t *value)
    {
        return unpickle(pos, end, *value);
    }


    std::uint8_t *_olm_pickle_bytes(std::uint8_t *pos, std::uint8_t const *bytes, size_t bytes_length)
    {
        return pickle_bytes(pos, bytes, bytes_length);
    }

    std::uint8_t const *_olm_unpickle_bytes(std::uint8_t const *pos, std::uint8_t const *end, std::uint8_t *bytes,
                                            size_t bytes_length)
    {
        return unpickle_bytes(pos, end, bytes, bytes_length);
    }


    static void
    rehash_part(std::array<std::array<std::uint8_t, MEGOLM_RATCHET_PART_LENGTH>, MEGOLM_RATCHET_PARTS> &data,
                const int rehash_from_part, const int rehash_to_part)
    {
        const auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

        hmac->set_key(HASH_KEY_SEEDS[rehash_to_part], HASH_KEY_SEED_LENGTH);
        hmac->update(data[rehash_from_part].data(), MEGOLM_RATCHET_PART_LENGTH);
        hmac->final(data[rehash_to_part].data());
    }


    void Megolm::init(Botan::RandomNumberGenerator &rng, const unsigned int counter)
    {
        this->counter = counter;
        for (auto &part : data)
        {
            rng.randomize(part.data(), part.size());
        }
    }

    size_t Megolm::pickle_length() const { return data.size() * data[0].size() + UINT32_LENGTH; }

    std::uint8_t *Megolm::pickle(std::uint8_t *pos) const
    {

        pos = _olm_pickle_bytes(pos, get_data(), MEGOLM_RATCHET_LENGTH);
        pos = _olm_pickle_uint32(pos, counter);
        return pos;
    }

    std::uint8_t const *Megolm::unpickle(std::uint8_t const *pos, const std::uint8_t *end)
    {
        pos = _olm_unpickle_bytes(pos, end, const_cast<std::uint8_t *>(get_data()), MEGOLM_RATCHET_LENGTH);
        UNPICKLE_OK(pos);

        pos = _olm_unpickle_uint32(pos, end, &counter);
        UNPICKLE_OK(pos);

        return pos;
    }

    void Megolm::advance()
    {
        counter++;
        uint32_t mask = 0x00FFFFFF;
        int h = 0;

        /* figure out how much we need to rekey */
        while (h < MEGOLM_RATCHET_PARTS && (counter & mask))
        {
            h++;
            mask >>= 8;
        }

        /* now update R(h)...R(3) based on R(h) */
        for (int i = MEGOLM_RATCHET_PARTS - 1; i >= h; i--)
        {
            rehash_part(data, h, i);
        }
    }

    void Megolm::advance(const unsigned int advance_to)
    {
        /* starting with R0, see if we need to update each part of the hash */
        for (int j = 0; j < MEGOLM_RATCHET_PARTS; j++)
        {
            const int shift = (MEGOLM_RATCHET_PARTS - j - 1) * 8;
            const uint32_t mask = (~static_cast<uint32_t>(0)) << shift;


            /* how many times do we need to rehash this part?
             *
             * '& 0xff' ensures we handle integer wraparound correctly
             */
            unsigned int steps = ((advance_to >> shift) - (counter >> shift)) & 0xff;

            if (steps == 0)
            {
                /* deal with the edge case where megolm->counter is slightly larger
                 * than advance_to. This should only happen for R(0), and implies
                 * that advance_to has wrapped around and we need to advance R(0)
                 * 256 times.
                 */
                if (advance_to < counter)
                {
                    steps = 0x100;
                }
                else
                {
                    continue;
                }
            }

            /* for all but the last step, we can just bump R(j) without regard
             * to R(j+1)...R(3).
             */
            while (steps-- > 1)
            {
                rehash_part(data, j, j);
            }

            /* on the last step we also need to bump R(j+1)...R(3).
             *
             * (Theoretically, we could skip bumping R(j+2) if we're going to bump
             * R(j+1) again, but the code to figure that out is a bit baroque and
             * doesn't save us much).
             */
            for (int k = 3; k >= j; k--)
            {
                rehash_part(data, j, k);
            }
            counter = advance_to & mask;
        }
    }

} // namespace spank_olm
