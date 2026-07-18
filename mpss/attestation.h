// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/defines.h"
#include <cstddef>
#include <optional>
#include <vector>

namespace mpss
{

enum class AttestationFormat
{
    none,
    apple_app_attest,
    android_key_attestation,
    windows_tpm
};

struct AttestationEvidence
{
    AttestationFormat format{AttestationFormat::none};
    std::vector<std::byte> statement;
    std::vector<std::vector<std::byte>> cert_chain;
};

enum class AttestationRequirement
{
    request,
    require
};

struct AttestationRequest
{
    std::vector<std::byte> challenge;
    AttestationRequirement requirement{AttestationRequirement::request};
};

} // namespace mpss
