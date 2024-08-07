#pragma once

#include <numeric>
#include <botan/x25519.h>
#include <botan/ed25519.h>
#include <botan/base64.h>

#include "list.hpp"

// Define a macro to detect Emscripten
#ifdef __EMSCRIPTEN__
#define EMSCRIPTEN_CONSTEXPR
#else
#define EMSCRIPTEN_CONSTEXPR constexpr
#endif

namespace spank_olm
{
    /**
     * \brief Represents identity keys containing both Ed25519 and Curve25519 key pairs.
     *
     * This struct aggregates an Ed25519 key pair for signing and a Curve25519 key pair
     * for encryption and key exchange.
     */
    struct IdentityKeys
    {
        Botan::Ed25519_PrivateKey ed25519_key;
        ///< The Ed25519 key pair for signing. The public key can be obtained using the public_key() method.
        Botan::X25519_PrivateKey curve25519_key;
        ///< The Curve25519 key pair for encryption and key exchange. The public key can be obtained using the public_key() method.
    };

    /**
     * \brief Represents a one-time key used in the encryption process.
     *
     * This struct contains an identifier, a publication status, and a Curve25519 key pair.
     */
    struct OneTimeKey
    {
        std::uint32_t id; ///< The unique identifier for the one-time key.
        bool published; ///< Indicates whether the key has been published.
        Botan::X25519_PrivateKey key; ///< The Curve25519 key pair for encryption and key exchange.
    };

    constexpr std::size_t MAX_ONE_TIME_KEYS(100); ///< The maximum number of one-time keys.

    struct Account
    {
        Account() : next_one_time_key_id(0)
        {
        }

        Account(Account const& other) = default;

        std::optional<IdentityKeys> identity_keys; ///< The identity keys for the account.
        FixedSizeArray<OneTimeKey, MAX_ONE_TIME_KEYS> one_time_keys; ///< The one-time keys for the account.
        std::optional<OneTimeKey> current_fallback_key; ///< The current fallback key.
        std::optional<OneTimeKey> prev_fallback_key; ///< The previous fallback key.
        std::uint32_t next_one_time_key_id; ///< The identifier for the next one-time key.

        /**
         * \brief Generates a new account with the given identity keys.
         *
         * \param rng The botan random number generator to use.
         * \return The result of the operation.
         * \throws SpankOlmErrorKeyGeneration if the key generation fails.
         */
        void new_account(Botan::RandomNumberGenerator& rng);

        /**
         * \brief Output the identity keys for this account as JSON.
         *
         * The output JSON will have the following format:
         *
         * ```json
         * {
         *   "curve25519": "<43 base64 characters>",
         *   "ed25519": "<43 base64 characters>"
         * }
         * ```
         *
         * \return The JSON representation of the identity keys.
         */
        [[nodiscard]] EMSCRIPTEN_CONSTEXPR std::string get_identity_json() const
        {
            auto curve25519_key = identity_keys->curve25519_key.public_key()->raw_public_key_bits();
            auto ed25519_key = identity_keys->ed25519_key.public_key()->raw_public_key_bits();

            const auto curve25519_base64 = Botan::base64_encode(curve25519_key);
            const auto ed25519_base64 = Botan::base64_encode(ed25519_key);

            return R"({"curve25519": ")" + curve25519_base64 +
                R"(", "ed25519": ")" + ed25519_base64 + "\"}";
        }

        /**
         * \brief Signs a message using the Ed25519 key.
         *
         * \param rng The botan random number generator to use.
         * \param message The message to sign.
         * \return The signature of the message.
         */
        [[nodiscard]] std::vector<uint8_t> sign(Botan::RandomNumberGenerator& rng, std::string_view message) const;


        /**
         * \brief Output the identity keys for this account as JSON.
         *
         * The output JSON will have the following format:
         *
         * ```json
         * {
         *   "curve25519": [
         *     "<6 byte key id>": "<43 base64 characters>",
         *     "<6 byte key id>": "<43 base64 characters>",
         *     ...
         *   ]
         * }
         * ```
         *
         * @return Returns the JSON representation of the one time keys which haven't been published yet.
         */
        [[nodiscard]] EMSCRIPTEN_CONSTEXPR std::string get_one_time_keys_json()
        {
            std::vector<std::string> stringified_keys;

            for (const auto& key : one_time_keys)
            {
                if (!key->published)
                {
                    auto key_base64 = Botan::base64_encode(key->key.public_key()->raw_public_key_bits());
                    stringified_keys.push_back(R"(")" + std::to_string(key->id) + R"(": ")" + key_base64 + "\"");
                }
            }

            const std::string keys_json = std::accumulate(
                stringified_keys.begin(), stringified_keys.end(), std::string(),
                [](const std::string& acc, const std::string& key)
                {
                    return acc.empty() ? key : acc + ", " + key;
                });

            return R"({"curve25519": {)" + keys_json + "}}";
        }

        /**
         * \brief Mark the curent list of one_time_keys and the current_fallback_key as published.
         *
         * The current one time keys will no longer be returned by
         * get_one_time_keys_json() and the current fallback key will no longer be
         * returned by get_unpublished_fallback_key_json().
         *
         * \return The count of keys marked as published.
         */
        std::size_t mark_keys_as_published();

        /**
         * \brief Returns the maximum number of one-time keys.
         *
         * This function provides the maximum number of one-time keys that can be stored
         * in the account. This value is defined by the constant MAX_ONE_TIME_KEYS.
         *
         * \return The maximum number of one-time keys.
         */
        [[nodiscard]] static constexpr std::size_t max_number_of_one_time_keys()
        {
            return MAX_ONE_TIME_KEYS;
        }

        /**
         * \brief Generates a number of new one-time keys.
         *
         * Generates a number of new one time keys. If the total number of keys
         * stored by this account exceeds max_number_of_one_time_keys() then the
         * old keys are discarded.
         */
        void generate_one_time_keys(Botan::RandomNumberGenerator& rng, std::size_t number_of_keys);

        /**
         * \brief Generates a new fallback key.
         */
        void generate_fallback_key(Botan::RandomNumberGenerator& rng);

        /**
         * \brief Output the currentöy unpublished fallback key as JSON.
         *
         * The output JSON will have the following format:
         *
         * ```json
         * {
         *   "curve25519": [
         *     "<6 byte key id>": "<43 base64 characters>",
         *     "<6 byte key id>": "<43 base64 characters>",
         *     ...
         *   ]
         * }
         * ```
         */
        [[nodiscard]] std::string EMSCRIPTEN_CONSTEXPR get_unpublished_fallback_key_json() const
        {
            if (!current_fallback_key || current_fallback_key->published)
            {
                return R"({"curve25519": {}})";
            }

            const auto key_base64 = Botan::base64_encode(current_fallback_key->key.public_key()->raw_public_key_bits());
            return R"({"curve25519": {")" + std::to_string(current_fallback_key->id) + R"(": ")" + key_base64 + "\"}}";
        }

        /**
         * \brief Forget about the old fallback key.
         */
        void forget_old_fallback_key();

        /**
         * \brief Lookup a one time key with the given public key
         */
        [[nodiscard]] std::optional<OneTimeKey const*> lookup_key(Botan::Public_Key const& key) const;

        /**
         * \brief Remove a one time key with the given public key
         */
        void remove_key(Botan::Public_Key const& key);

        [[nodiscard]] std::vector<uint8_t> pickle() const;

        static Account unpickle(std::vector<uint8_t> const& data);
    };
}



