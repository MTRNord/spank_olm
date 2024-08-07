#include "spank-olm.hpp"

// Binding code for emscripten using embind. It should only be included when compiling for Emscripten.
#ifdef __EMSCRIPTEN__
#include <emscripten/bind.h>
#include <botan/rng.h>
#include <botan/der_enc.h>

EMSCRIPTEN_BINDINGS(spank_olm)
{
    using namespace emscripten;
    class_<spank_olm::Account>("Account")
       .constructor<>()
       .function("new_account", &spank_olm::Account::new_account)
       .function("sign", &spank_olm::Account::sign)
       .function("mark_keys_as_published", &spank_olm::Account::mark_keys_as_published)
       .function("generate_one_time_keys", &spank_olm::Account::generate_one_time_keys)
       .function("generate_fallback_key", &spank_olm::Account::generate_fallback_key)
       .function("forget_old_fallback_key", &spank_olm::Account::forget_old_fallback_key)
       .function("lookup_key", &spank_olm::Account::lookup_key)
       .function("remove_key", &spank_olm::Account::remove_key)
       .function("pickle", &spank_olm::Account::pickle)
       .function("unpickle", &spank_olm::Account::unpickle)
       .property("identity_keys", &spank_olm::Account::identity_keys, return_value_policy::reference())
       .property("one_time_keys", &spank_olm::Account::one_time_keys, return_value_policy::reference())
       .property("current_fallback_key", &spank_olm::Account::current_fallback_key, return_value_policy::reference())
       .property("prev_fallback_key", &spank_olm::Account::prev_fallback_key, return_value_policy::reference())
       .property("next_one_time_key_id", &spank_olm::Account::next_one_time_key_id, return_value_policy::reference());

    constant("MAX_ONE_TIME_KEYS", spank_olm::MAX_ONE_TIME_KEYS);

    register_optional<spank_olm::IdentityKeys>();
    register_optional<spank_olm::OneTimeKey>();
    register_optional<spank_olm::OneTimeKey const*>();

    class_<Botan::Public_Key>("Public_Key");
    class_<Botan::X25519_PrivateKey>("X25519_PrivateKey");
    class_<Botan::RandomNumberGenerator>("RandomNumberGenerator");


    // Register Ed25519_PrivateKey which cant be default constructed
    class_<Botan::Ed25519_PrivateKey>("Ed25519_PrivateKey");

    // Register the secure_vector type for use in the Account struct.
    // Note that this is downcasted to a vector of uint8_t instead of the original type.
    register_vector<Botan::uint8_t>("SecureVector");

    // Register string_view for use in the Account struct.
    class_<std::string_view>("string_view")
        .constructor<>();

    // Register OneTimeKey which cant be default constructed
    class_<spank_olm::OneTimeKey>("OneTimeKey")
        .constructor<std::uint32_t, bool, Botan::X25519_PrivateKey>();

    // Register IdentityKeys which cant be default constructed
    class_<spank_olm::IdentityKeys>("IdentityKeys")
        .constructor<Botan::Ed25519_PrivateKey, Botan::X25519_PrivateKey>();

    // Register FixedSizeArray
    class_<spank_olm::FixedSizeArray<spank_olm::OneTimeKey, spank_olm::MAX_ONE_TIME_KEYS>>("FixedSizeArrayOneTimeKeys");
}
#endif
