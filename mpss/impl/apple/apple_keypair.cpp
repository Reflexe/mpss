// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/apple/apple_keypair.h"
#include "mpss/utils/utilities.h"

namespace mpss::impl::os
{

AppleKeyPairBase::AppleKeyPairBase(std::string_view name, Algorithm algorithm, SecurityType security_type,
                                   const char *storage_description)
    : KeyPair{algorithm, security_type, storage_description}, name_{name}
{
}

void AppleKeyPairBase::release_key()
{
    do_release_key();
}

} // namespace mpss::impl::os
