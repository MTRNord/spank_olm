#pragma once
#include <account.hpp>

namespace spank_olm
{

    /**
     * Serializes a 32-bit unsigned integer into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The 32-bit unsigned integer to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, std::uint32_t value);

    /**
     * Deserializes a 32-bit unsigned integer from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the 32-bit unsigned integer to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or
     * nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::uint32_t &value);

    /**
     * Serializes a boolean value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The boolean value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, bool value);

    /**
     * Deserializes a boolean value from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the boolean value to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, bool &value);

    /**
     * Serializes a Botan::secure_vector<uint8_t> into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The Botan::secure_vector<uint8_t> to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const Botan::secure_vector<uint8_t> &value);

    /**
     * Deserializes a Botan::secure_vector<uint8_t> from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the Botan::secure_vector<uint8_t> to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end,
                                 Botan::secure_vector<uint8_t> &value);

    /**
     * Serializes a std::vector<uint8_t> into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The Botan::secure_vector<uint8_t> to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const std::vector<uint8_t> &value);

    /**
     * Deserializes a std::vector<uint8_t> from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the Botan::secure_vector<uint8_t> to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::vector<uint8_t> &value);

    /**
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value A OneTimeKey object to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const std::optional<OneTimeKey> &value);

    /**
     * Deserializes a OneTimeKey object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @return A pair containing the pointer to the position in the byte array after the deserialized data and the
     * deserialized OneTimeKey object.
     */
    static std::pair<std::uint8_t const *, std::optional<OneTimeKey>> unpickle_otk(std::uint8_t const *pos,
                                                                                   std::uint8_t const *end);

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
    std::uint8_t *pickle(std::uint8_t *pos, FixedSizeArray<T, max_size> const &list);

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
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end,
                                 FixedSizeArray<OneTimeKey, max_size> &list);

    /**
     * Serializes a uint8_t value into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The uint8_t value to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, std::uint8_t value);

    /**
     * Deserializes a uint8_t value from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the uint8_t value to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::uint8_t &value);

    /**
     * Serializes an optional IdentityKeys object into a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param value The optional IdentityKeys object to serialize.
     * @return Pointer to the position in the byte array after the serialized data.
     */
    std::uint8_t *pickle(std::uint8_t *pos, const std::optional<IdentityKeys> &value);

    /**
     * Deserializes an optional IdentityKeys object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the optional IdentityKeys object to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::optional<IdentityKeys> &value);

    /**
     * Deserializes an optional OneTimeKey object from a byte array.
     *
     * @param pos Pointer to the current position in the byte array.
     * @param end Pointer to the end of the byte array.
     * @param value Reference to the optional OneTimeKey object to store the deserialized value.
     * @return Pointer to the position in the byte array after the deserialized data, or nullptr on failure.
     */
    std::uint8_t const *unpickle(std::uint8_t const *pos, std::uint8_t const *end, std::optional<OneTimeKey> &value);

    std::uint8_t *pickle_bytes(std::uint8_t *pos, const std::uint8_t *bytes, const std::size_t bytes_length);

    std::uint8_t const *unpickle_bytes(const std::uint8_t *pos, const std::uint8_t *end, std::uint8_t *bytes,
                                       const std::size_t bytes_length);
} // namespace spank_olm
