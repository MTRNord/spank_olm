#include "pickle.hpp"

#include <botan/x25519.h>

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


namespace spank_olm
{

    /**
     * Serializes a 32-bit unsigned integer into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The 32-bit unsigned integer to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, std::uint32_t value)
    {
        for (int i = 3; i >= 0; --i)
        {
            pos[i] = value & 0xFF;
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::uint32_t &value)
    {
        if (!pos || end < pos + 4)
            return nullptr;
        value = (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
        return pos + 4;
    }

    /**
     * Serializes a boolean value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The boolean value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const bool value)
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, bool &value)
    {
        if (!pos || end <= pos)
            return nullptr;
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
    std::uint8_t *pickle(std::uint8_t *pos, const Botan::secure_vector<uint8_t> &value)
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, Botan::secure_vector<uint8_t> &value)
    {
        std::uint32_t size;
        pos = unpickle(pos, end, size);
        if (!pos || end < pos + size)
            return nullptr;
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
    std::uint8_t *pickle(std::uint8_t *pos, const std::vector<uint8_t> &value)
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::vector<uint8_t> &value)
    {
        std::uint32_t size;
        pos = unpickle(pos, end, size);
        if (!pos || end < pos + size)
            return nullptr;
        value.assign(pos, pos + size);
        return pos + size;
    }

    /**
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value A OneTimeKey object to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const std::optional<OneTimeKey> &value)
    {
        pos = pickle(pos, value->id);
        pos = pickle(pos, value->published);
        return pickle(pos, value->key.raw_private_key_bits());
    }

    /**
     * Deserializes a OneTimeKey object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @return A pair containing the pointer to the position in the byte array after the deserialized data and the
     * deserialized OneTimeKey object.
     */
    std::pair<std::uint8_t const *, std::optional<OneTimeKey>> unpickle_otk(std::uint8_t const *pos,
                                                                            std::uint8_t const *end)
    {
        std::uint32_t id; ///< The unique identifier for the one-time key.
        bool published; ///< Indicates whether the key has been published.

        pos = unpickle(pos, end, id);
        if (!pos || !id)
        {
            return {nullptr, std::nullopt};
        }
        pos = unpickle(pos, end, published);
        if (!pos)
            return {nullptr, std::nullopt};

        Botan::secure_vector<uint8_t> key_bits;
        pos = unpickle(pos, end, key_bits);
        if (!pos)
            return {nullptr, std::nullopt};

        auto otk = OneTimeKey{id, published, Botan::X25519_PrivateKey(key_bits)};

        return {pos, otk};
    }

    /**
     * Serializes a uint8_t value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The uint8_t value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const std::uint8_t value)
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::uint8_t &value)
    {
        if (!pos || pos == end)
            return nullptr;
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
    std::uint8_t *pickle(std::uint8_t *pos, const std::optional<IdentityKeys> &value)
    {
        pos = pickle(pos, value->ed25519_key.public_key()->raw_public_key_bits());
        pos = pickle(pos, value->ed25519_key.raw_private_key_bits());
        pos = pickle(pos, value->curve25519_key.public_key()->raw_public_key_bits());
        return pickle(pos, value->curve25519_key.raw_private_key_bits());
    }

    /**
     * Deserializes an optional IdentityKeys object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the optional IdentityKeys object to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::optional<IdentityKeys> &value)
    {
        if (!pos || pos == end)
            return nullptr;
        Botan::secure_vector<uint8_t> ed25519_public_key_bits;
        Botan::secure_vector<uint8_t> curve25519_public_key_bits;
        Botan::secure_vector<uint8_t> ed25519_private_key_bits;
        Botan::secure_vector<uint8_t> curve25519_private_key_bits;

        pos = unpickle(pos, end, ed25519_public_key_bits);
        UNPICKLE_OK(pos);
        pos = unpickle(pos, end, ed25519_private_key_bits);
        UNPICKLE_OK(pos);
        pos = unpickle(pos, end, curve25519_public_key_bits);
        UNPICKLE_OK(pos);
        pos = unpickle(pos, end, curve25519_private_key_bits);
        UNPICKLE_OK(pos);
        value = IdentityKeys{Botan::Ed25519_PrivateKey::from_bytes(ed25519_private_key_bits),
                             Botan::X25519_PrivateKey(curve25519_private_key_bits)};
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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::optional<OneTimeKey> &value)
    {
        if (!pos || pos == end)
            return nullptr;
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

    std::uint8_t *pickle_bytes(std::uint8_t *pos, const std::uint8_t *bytes, const std::size_t bytes_length)
    {
        std::memcpy(pos, bytes, bytes_length);
        return pos + bytes_length;
    }

    std::uint8_t const *unpickle_bytes(const std::uint8_t *pos, const std::uint8_t *end, std::uint8_t *bytes,
                                       const std::size_t bytes_length)
    {
        if (!pos || end < pos + bytes_length)
            return nullptr;
        std::memcpy(bytes, pos, bytes_length);
        return pos + bytes_length;
    }

} // namespace spank_olm
