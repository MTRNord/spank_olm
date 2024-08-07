#include "account.hpp"
#include "errors.hpp"

#include <botan/pubkey.h>
#include <botan/auto_rng.h>

/* Convenience macro for checking the return value of internal unpickling
 * functions and returning early on failure. */
#ifndef UNPICKLE_OK
#define UNPICKLE_OK(x) do { if (!(x)) return NULL; } while(0)
#endif


namespace spank_olm
{
    /**
 * Serializes a 32-bit unsigned integer into a byte array.
 *
 * @param pos Pointer to the current position in the byte array.
 * @param value The 32-bit unsigned integer to serialize.
 * @return Pointer to the position in the byte array after the serialized data.
 */
    std::uint8_t* pickle(std::uint8_t* pos, std::uint32_t value)
    {
        pos += 4;
        for (unsigned i = 4; i--;)
        {
            *(--pos) = value;
            value >>= 8;
        }
        return pos + 4;
    }

    /**
     * Deserializes a 32-bit unsigned integer from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the 32-bit unsigned integer to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(std::uint8_t const* pos, std::uint8_t const* end, std::uint32_t& value)
    {
        value = 0;
        if (!pos || end < pos + 4) return nullptr;
        for (unsigned i = 4; i--;)
        {
            value <<= 8;
            value |= *(pos++);
        }
        return pos;
    }

    /**
     * Serializes a boolean value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The boolean value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t* pickle(std::uint8_t* pos, const bool value)
    {
        *(pos++) = value ? 1 : 0;
        return pos;
    }

    /**
     * Deserializes a boolean value from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the boolean value to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(std::uint8_t const* pos, std::uint8_t const* end, bool& value)
    {
        if (!pos || end <= pos) return nullptr;
        value = *(pos++) != 0;
        return pos;
    }

    /**
     * Serializes a Botan::secure_vector<uint8_t> into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The Botan::secure_vector<uint8_t> to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t* pickle(std::uint8_t* pos, const Botan::secure_vector<uint8_t>& value)
    {
        pos = pickle(pos, static_cast<std::uint32_t>(value.size()));
        for (const auto byte : value)
        {
            *(pos++) = byte;
        }
        return pos;
    }

    /**
     * Deserializes a Botan::secure_vector<uint8_t> from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the Botan::secure_vector<uint8_t> to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(std::uint8_t const* pos, std::uint8_t const* end, Botan::secure_vector<uint8_t>& value)
    {
        std::uint32_t size;
        pos = unpickle(pos, end, size);
        if (!pos || end < pos + size) return nullptr;
        value.assign(pos, pos + size);
        return pos + size;
    }


    /**
   * Serializes a std::vector<uint8_t> into a byte array.
   *
   * @param pos Pointer to the current position in the byte array.
   * @param value The Botan::secure_vector<uint8_t> to serialize.
   * @return Pointer to the position in the byte array after the serialized data.
   */
    std::uint8_t* pickle(std::uint8_t* pos, const std::vector<uint8_t>& value)
    {
        pos = pickle(pos, static_cast<std::uint32_t>(value.size()));
        for (const auto byte : value)
        {
            *(pos++) = byte;
        }
        return pos;
    }

    /**
     * Deserializes a std::vector<uint8_t> from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the Botan::secure_vector<uint8_t> to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(std::uint8_t const* pos, std::uint8_t const* end, std::vector<uint8_t>& value)
    {
        std::uint32_t size;
        pos = unpickle(pos, end, size);
        if (!pos || end < pos + size) return nullptr;
        value.assign(pos, pos + size);
        return pos + size;
    }

    std::uint8_t* pickle(
        std::uint8_t* pos,
        const std::optional<OneTimeKey>& value)
    {
        pos = pickle(pos, value->id);
        pos = pickle(pos, value->published);
        pos = pickle(pos, value->key.raw_private_key_bits());
        return pos;
    }

    /**
     * Deserializes a OneTimeKey object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @return A pair containing the pointer to the position in the byte array after the deserialized data and the deserialized OneTimeKey object.
     */
    static std::pair<std::uint8_t const*, std::optional<OneTimeKey>> unpickle_otk(
        std::uint8_t const* pos, std::uint8_t const* end
    )
    {
        std::uint32_t id; ///< The unique identifier for the one-time key.
        bool published; ///< Indicates whether the key has been published.

        pos = unpickle(pos, end, id);
        if (!id)
        {
            return {nullptr, std::nullopt};
        }
        pos = unpickle(pos, end, published);
        Botan::secure_vector<uint8_t> key_bits;
        pos = unpickle(pos, end, key_bits);
        auto otk = OneTimeKey{id, published, Botan::X25519_PrivateKey(key_bits)};

        return {pos, otk};
    }

    /**
     * Serializes a FixedSizeArray object into a byte array.
     *
     * @tparam T The type of elements in the FixedSizeArray.
     * @tparam max_size The maximum size of the FixedSizeArray.
     * @param pos Pointer to the current position in the byte array.
     * @param list The FixedSizeArray object to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    template <typename T, std::size_t max_size>
    std::uint8_t* pickle(
        std::uint8_t* pos,
        FixedSizeArray<T, max_size> const& list
    )
    {
        pos = pickle(pos, static_cast<std::uint32_t>(list.size()));
        for (auto const& value : list)
        {
            pos = pickle(pos, *value);
        }
        return pos;
    }

    /**
     * Deserializes a FixedSizeArray object from a byte array.
     *
     * @tparam max_size The maximum size of the FixedSizeArray.
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param list Reference to the FixedSizeArray object to store the deserialized values.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    template <std::size_t max_size>
    std::uint8_t const* unpickle(
        std::uint8_t const* pos, std::uint8_t const* end,
        FixedSizeArray<OneTimeKey, max_size>& list
    )
    {
        std::uint32_t size;
        pos = unpickle(pos, end, size);
        if (!pos)
        {
            return nullptr;
        }

        while (size-- && pos != end)
        {
            auto [temp_pos, value] = unpickle_otk(pos, end);
            pos = temp_pos;
            if (!pos)
            {
                return nullptr;
            }
            list.insert(value.value());
        }

        return pos;
    }

    /**
     * Serializes a uint8_t value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The uint8_t value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t* pickle(
        std::uint8_t* pos,
        const std::uint8_t value
    )
    {
        *(pos++) = value;
        return pos;
    }

    /**
     * Deserializes a uint8_t value from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the uint8_t value to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(
        std::uint8_t const* pos, std::uint8_t const* end,
        std::uint8_t& value
    )
    {
        if (!pos || pos == end) return nullptr;
        value = *(pos++);
        return pos;
    }

    /**
     * Serializes an optional IdentityKeys object into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The optional IdentityKeys object to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t* pickle(
        std::uint8_t* pos,
        const std::optional<IdentityKeys>& value)
    {
        pos = pickle(pos, value->ed25519_key.public_key()->raw_public_key_bits());
        pos = pickle(pos, value->ed25519_key.raw_private_key_bits());
        pos = pickle(pos, value->curve25519_key.public_key()->raw_public_key_bits());
        pos = pickle(pos, value->curve25519_key.raw_private_key_bits());
        return pos;
    }

    /**
     * Deserializes an optional IdentityKeys object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the optional IdentityKeys object to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(
        std::uint8_t const* pos, std::uint8_t const* end,
        std::optional<IdentityKeys>& value)
    {
        if (!pos || pos == end) return nullptr;
        Botan::secure_vector<uint8_t> ed25519_public_key_bits;
        pos = unpickle(pos, end, ed25519_public_key_bits);
        UNPICKLE_OK(pos);
        Botan::secure_vector<uint8_t> ed25519_private_key_bits;
        pos = unpickle(pos, end, ed25519_private_key_bits);
        UNPICKLE_OK(pos);
        Botan::secure_vector<uint8_t> curve25519_public_key_bits;
        pos = unpickle(pos, end, curve25519_public_key_bits);
        UNPICKLE_OK(pos);
        Botan::secure_vector<uint8_t> curve25519_private_key_bits;
        pos = unpickle(pos, end, curve25519_private_key_bits);
        UNPICKLE_OK(pos);
        value = IdentityKeys{
            Botan::Ed25519_PrivateKey(ed25519_private_key_bits),
            Botan::X25519_PrivateKey(curve25519_private_key_bits)
        };
        return pos;
    }

    /**
     * Deserializes an optional OneTimeKey object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the optional OneTimeKey object to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const* unpickle(
        std::uint8_t const* pos, std::uint8_t const* end,
        std::optional<OneTimeKey>& value)
    {
        if (!pos || pos == end) return nullptr;
        std::uint32_t id;
        bool published;
        Botan::secure_vector<uint8_t> key_bits;
        pos = unpickle(pos, end, id);
        UNPICKLE_OK(pos);
        pos = unpickle(pos, end, published);
        UNPICKLE_OK(pos);
        pos = unpickle(pos, end, key_bits);
        UNPICKLE_OK(pos);
        value = OneTimeKey{id, published, Botan::X25519_PrivateKey(key_bits)};
        return pos;
    }

    void Account::new_account(Botan::RandomNumberGenerator& rng)
    {
        identity_keys = IdentityKeys{
            Botan::Ed25519_PrivateKey(rng),
            Botan::X25519_PrivateKey(rng)
        };

        // Make sure we check the key pairs.
        if (!identity_keys->ed25519_key.check_key(rng, false) ||
            !identity_keys->curve25519_key.check_key(rng, false))
        {
            throw SpankOlmErrorKeyGeneration();
        }

        // Verify the public keys using the respective check_key methods.
        if (!identity_keys->ed25519_key.public_key()->check_key(rng, false) ||
            !identity_keys->curve25519_key.public_key()->check_key(rng, false))
        {
            throw SpankOlmErrorKeyGeneration();
        }
    }

    std::vector<uint8_t> Account::sign(const std::string_view message) const
    {
        Botan::AutoSeeded_RNG rng;

        // According to https://botan.randombit.net/handbook/api_ref/pubkey.html#ed25519-ed448-variants
        const std::string padding_scheme = "Ed25519ph";

        // Use the Ed25519 key to sign the message using the Botan library.


        Botan::PK_Signer signer(identity_keys->ed25519_key, rng, padding_scheme);
        signer.update(message);
        auto signature = signer.signature(rng);

        return signature;
    }

    std::size_t Account::mark_keys_as_published()
    {
        auto count = 0;
        for (const auto& key : one_time_keys)
        {
            if (!key->published)
            {
                key->published = true;
                count++;
            }
        }

        current_fallback_key->published = true;
        return count;
    }

    void Account::generate_one_time_keys(Botan::RandomNumberGenerator& rng, const std::size_t number_of_keys)
    {
        for (std::size_t i = 0; i < number_of_keys; ++i)
        {
            one_time_keys.insert(OneTimeKey{++next_one_time_key_id, false, Botan::X25519_PrivateKey(rng)});
        }
    }

    void Account::generate_fallback_key(Botan::RandomNumberGenerator& rng)
    {
        if (num_fallback_keys < 2)
        {
            num_fallback_keys++;
        }
        prev_fallback_key = current_fallback_key;
        current_fallback_key = OneTimeKey{++next_one_time_key_id, false, Botan::X25519_PrivateKey(rng)};
    }

    void Account::forget_old_fallback_key()
    {
        if (num_fallback_keys >= 2)
        {
            num_fallback_keys = 1;
            // TODO: Verify if this is correct.
            prev_fallback_key.reset();
        }
    }

    std::optional<OneTimeKey const*> Account::lookup_key(Botan::Public_Key const& key) const
    {
        for (const auto& one_time_key : one_time_keys)
        {
            if (one_time_key->key.public_key()->raw_public_key_bits() == key.raw_public_key_bits())
            {
                return one_time_key;
            }
        }
        if (num_fallback_keys >= 1 && current_fallback_key->key.public_key()->raw_public_key_bits() == key.
            raw_public_key_bits())
        {
            return &current_fallback_key.value();
        }
        if (num_fallback_keys >= 2 && prev_fallback_key->key.public_key()->raw_public_key_bits() == key.
            raw_public_key_bits())
        {
            return &current_fallback_key.value();
        }
        return std::nullopt;
    }

    void Account::remove_key(Botan::Public_Key const& key)
    {
        // Use iterator to find and remove the key.
        for (const auto& one_time_key : one_time_keys)
        {
            if (one_time_key->key.public_key()->raw_public_key_bits() == key.raw_public_key_bits())
            {
                one_time_keys.erase(one_time_key);
                return;
            }
        }
    }


    namespace
    {
        /**
         * \brief The current version of the account pickle format.
         *
         * \details
         * - Version 1 used only 32 bytes for the ed25519 private key. Any keys thus used should be considered compromised.
         * - Version 2 does not have fallback keys.
         * - Version 3 does not store whether the current fallback key is published.
         */
        constexpr std::uint32_t ACCOUNT_PICKLE_VERSION = 4;
    }


    /**
 * Serializes the Account object into a byte array.
 *
 * @return A vector of uint8_t containing the serialized data.
 */
    std::vector<uint8_t> Account::pickle() const
    {
        std::vector<uint8_t> buffer(1024); // Initial buffer size, can be adjusted
        auto pos = buffer.data();

        pos = spank_olm::pickle(pos, ACCOUNT_PICKLE_VERSION);

        pos = spank_olm::pickle(pos, identity_keys);

        pos = spank_olm::pickle(pos, one_time_keys);

        pos = spank_olm::pickle(pos, num_fallback_keys);

        if (num_fallback_keys >= 1)
        {
            pos = spank_olm::pickle(pos, current_fallback_key);
            if (num_fallback_keys >= 2)
            {
                pos = spank_olm::pickle(pos, prev_fallback_key);
            }
        }

        pos = spank_olm::pickle(pos, next_one_time_key_id);

        buffer.resize(pos - buffer.data()); // Adjust buffer size to actual data size
        return buffer;
    }

    /**
     * Deserializes an Account object from a byte array.
     *
     * @param data A vector of uint8_t containing the serialized data.
     * @return The deserialized Account object.
     * @throws SpankOlmErrorVersionNotFound if the pickle version is not found.
     * @throws SpankOlmErrorBadLegacyAccountPickle if the pickle version is 1.
     * @throws SpankOlmErrorUnknownPickleVersion if the pickle version is unknown.
     * @throws SpankOlmErrorCorruptedAccountPickle if the pickle data is corrupted.
     */
    Account Account::unpickle(std::vector<uint8_t> const& data)
    {
        Account value;
        auto pos = data.data();
        const auto end = data.data() + data.size();
        uint32_t pickle_version;

        pos = spank_olm::unpickle(pos, end, pickle_version);
        if (!pos)
        {
            throw SpankOlmErrorVersionNotFound();
        }

        switch (pickle_version)
        {
        case ACCOUNT_PICKLE_VERSION:
        case 3:
        case 2:
            break;
        case 1:
            throw SpankOlmErrorBadLegacyAccountPickle();
        default:
            throw SpankOlmErrorUnknownPickleVersion();
        }

        pos = spank_olm::unpickle(pos, end, value.identity_keys);
        if (!pos)
        {
            throw SpankOlmErrorCorruptedAccountPickle();
        }
        pos = spank_olm::unpickle(pos, end, value.one_time_keys);
        if (!pos)
        {
            throw SpankOlmErrorCorruptedAccountPickle();
        }

        if (pickle_version <= 2)
        {
            value.num_fallback_keys = 0;
        }
        else if (pickle_version == 3)
        {
            pos = spank_olm::unpickle(pos, end, value.current_fallback_key);
            if (!pos)
            {
                throw SpankOlmErrorCorruptedAccountPickle();
            }
            pos = spank_olm::unpickle(pos, end, value.prev_fallback_key);
            if (!pos)
            {
                throw SpankOlmErrorCorruptedAccountPickle();
            }
            if (value.current_fallback_key->published)
            {
                if (value.prev_fallback_key->published)
                {
                    value.num_fallback_keys = 2;
                }
                else
                {
                    value.num_fallback_keys = 1;
                }
            }
            else
            {
                value.num_fallback_keys = 0;
            }
        }
        else
        {
            pos = spank_olm::unpickle(pos, end, value.num_fallback_keys);
            if (!pos)
            {
                throw SpankOlmErrorCorruptedAccountPickle();
            }
            if (value.num_fallback_keys >= 1)
            {
                pos = spank_olm::unpickle(pos, end, value.current_fallback_key);
                if (!pos)
                {
                    throw SpankOlmErrorCorruptedAccountPickle();
                }
                if (value.num_fallback_keys >= 2)
                {
                    pos = spank_olm::unpickle(pos, end, value.prev_fallback_key);
                    if (!pos)
                    {
                        throw SpankOlmErrorCorruptedAccountPickle();
                    }
                    if (value.num_fallback_keys >= 3)
                    {
                        throw SpankOlmErrorCorruptedAccountPickle();
                    }
                }
            }
        }

        pos = spank_olm::unpickle(pos, end, value.next_one_time_key_id);
        if (!pos)
        {
            throw SpankOlmErrorCorruptedAccountPickle();
        }

        return value;
    }
}
