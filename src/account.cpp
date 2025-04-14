#include "account.hpp"
#include "errors.hpp"
#include "pickle.hpp"

#include <botan/pubkey.h>
#include <botan/rng.h>

namespace spank_olm
{

    void Account::new_account(Botan::RandomNumberGenerator &rng)
    {
        identity_keys = IdentityKeys{Botan::Ed25519_PrivateKey(rng), Botan::X25519_PrivateKey(rng)};

        // Make sure we check the key pairs.
        if (!identity_keys->ed25519_key.check_key(rng, false) || !identity_keys->curve25519_key.check_key(rng, false) ||
            !identity_keys->ed25519_key.public_key()->check_key(rng, false) ||
            !identity_keys->curve25519_key.public_key()->check_key(rng, false))
        {
            throw SpankOlmErrorKeyGeneration();
        }
    }

    std::vector<uint8_t> Account::sign(Botan::RandomNumberGenerator &rng, const std::string_view message) const
    {
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
        for (const auto &key : one_time_keys)
        {
            if (!key->published)
            {
                key->published = true;
                ++count;
            }
        }

        current_fallback_key->published = true;
        return count;
    }

    void Account::generate_one_time_keys(Botan::RandomNumberGenerator &rng, const std::size_t number_of_keys)
    {
        for (std::size_t i = 0; i < number_of_keys; ++i)
        {
            one_time_keys.insert({++next_one_time_key_id, false, Botan::X25519_PrivateKey(rng)});
        }
    }

    void Account::generate_fallback_key(Botan::RandomNumberGenerator &rng)
    {
        prev_fallback_key = current_fallback_key;
        current_fallback_key = OneTimeKey{++next_one_time_key_id, false, Botan::X25519_PrivateKey(rng)};
    }

    void Account::forget_old_fallback_key()
    {
        if (current_fallback_key && prev_fallback_key)
        {
            // TODO: Verify if this is correct.
            prev_fallback_key.reset();
        }
    }

    std::optional<OneTimeKey const *> Account::lookup_key(Botan::Public_Key const &key) const
    {
        for (const auto &one_time_key : one_time_keys)
        {
            if (one_time_key->key.public_key()->raw_public_key_bits() == key.raw_public_key_bits())
            {
                return one_time_key;
            }
        }
        if (current_fallback_key &&
            current_fallback_key->key.public_key()->raw_public_key_bits() == key.raw_public_key_bits())
        {
            return &current_fallback_key.value();
        }
        if (prev_fallback_key &&
            prev_fallback_key->key.public_key()->raw_public_key_bits() == key.raw_public_key_bits())
        {
            return &current_fallback_key.value();
        }
        return std::nullopt;
    }

    void Account::remove_key(Botan::Public_Key const &key)
    {
        // Use iterator to find and remove the key.
        for (const auto &one_time_key : one_time_keys)
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
         * - Version 1 used only 32 bytes for the ed25519 private key. Any keys thus used should be considered
         * compromised.
         * - Version 2 does not have fallback keys.
         * - Version 3 does not store whether the current fallback key is published.
         */
        constexpr std::uint32_t ACCOUNT_PICKLE_VERSION = 4;
    } // namespace


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

        // Calculate the number of fallback keys
        std::uint8_t fallback_key_count = 0;
        if (current_fallback_key && current_fallback_key->published)
            fallback_key_count++;
        if (prev_fallback_key && prev_fallback_key->published)
            fallback_key_count++;

        // Serialize the fallback key count
        pos = spank_olm::pickle(pos, fallback_key_count);

        if (current_fallback_key)
        {
            pos = spank_olm::pickle(pos, current_fallback_key);
            if (prev_fallback_key)
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
    Account Account::unpickle(std::vector<uint8_t> const &data)
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

        if (pickle_version == 3)
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
        }
        else
        {
            std::uint8_t num_fallback_keys;
            pos = spank_olm::unpickle(pos, end, num_fallback_keys);
            if (!pos)
            {
                throw SpankOlmErrorCorruptedAccountPickle();
            }
            if (num_fallback_keys >= 1)
            {
                pos = spank_olm::unpickle(pos, end, value.current_fallback_key);
                if (!pos)
                {
                    throw SpankOlmErrorCorruptedAccountPickle();
                }
                if (num_fallback_keys >= 2)
                {
                    pos = spank_olm::unpickle(pos, end, value.prev_fallback_key);
                    if (!pos)
                    {
                        throw SpankOlmErrorCorruptedAccountPickle();
                    }
                    if (num_fallback_keys >= 3)
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
} // namespace spank_olm
