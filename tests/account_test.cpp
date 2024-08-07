#include <snitch/snitch.hpp>
#include "account.hpp"
#include "errors.hpp"
#include <botan/auto_rng.h>
#include <botan/pubkey.h>

using namespace spank_olm;

TEST_CASE("Account serialization and deserialization")
{
    Botan::AutoSeeded_RNG rng;
    Account account;
    account.new_account(rng);
    account.generate_one_time_keys(rng, 5);
    account.generate_fallback_key(rng);

    const auto serialized = account.pickle();
    const auto deserialized = Account::unpickle(serialized);

    REQUIRE(
        account.identity_keys->ed25519_key.public_key()->raw_public_key_bits() == deserialized.identity_keys->
        ed25519_key.public_key()->raw_public_key_bits());
    REQUIRE(
        account.identity_keys->curve25519_key.public_key()->raw_public_key_bits() == deserialized.identity_keys->
        curve25519_key.public_key()->raw_public_key_bits());
    REQUIRE(account.one_time_keys.size() == deserialized.one_time_keys.size());
    REQUIRE(account.next_one_time_key_id == deserialized.next_one_time_key_id);
}

TEST_CASE("Account sign and verify")
{
    Botan::AutoSeeded_RNG rng;
    Account account;
    account.new_account(rng);

    const std::string message = "Test message";
    auto signature = account.sign(rng, message);

    Botan::PK_Verifier verifier(account.identity_keys->ed25519_key, "Ed25519ph");
    verifier.update(message);
    REQUIRE(verifier.check_signature(signature));
}

TEST_CASE("Account generate and mark keys as published")
{
    Botan::AutoSeeded_RNG rng;
    Account account;
    account.new_account(rng);
    account.generate_one_time_keys(rng, 5);

    REQUIRE(account.one_time_keys.size() == 5);

    const auto published_count = account.mark_keys_as_published();
    REQUIRE(published_count == 5);

    for (const auto& key : account.one_time_keys)
    {
        REQUIRE(key->published == true);
    }
}

TEST_CASE("Account generate and forget fallback key")
{
    Botan::AutoSeeded_RNG rng;
    Account account;
    account.new_account(rng);
    account.generate_fallback_key(rng);


    account.generate_fallback_key(rng);

    account.forget_old_fallback_key();
    REQUIRE(account.prev_fallback_key == std::nullopt);
}

TEST_CASE("Account lookup and remove key")
{
    Botan::AutoSeeded_RNG rng;
    Account account;
    account.new_account(rng);
    account.generate_one_time_keys(rng, 1);

    const auto key = account.one_time_keys[0].key.public_key();
    auto lookup_result = account.lookup_key(*key);
    REQUIRE(lookup_result.has_value());

    account.remove_key(*key);
    lookup_result = account.lookup_key(*key);
    REQUIRE(!lookup_result.has_value());
}
