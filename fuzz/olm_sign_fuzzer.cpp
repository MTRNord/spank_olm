#include <botan/auto_rng.h>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include "account.hpp"
#include "botan/pubkey.h"

// Just needed for compiling reasons
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size == 0)
    {
        return -1;
    }

    spank_olm::Account account;
    Botan::AutoSeeded_RNG rng;
    account.new_account(rng);

    const std::string_view message(reinterpret_cast<const char *>(Data), Size);
    auto signature = account.sign(rng, message);

    // Verify the signature
    Botan::PK_Verifier verifier(account.identity_keys->ed25519_key, "Ed25519ph");
    verifier.update(message);
    assert(verifier.check_signature(signature));

    return 0;
}
