// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "mpss/attestation.h"

namespace mpss::impl::os
{

enum class AppleAttestationSelection
{
    none,
    app_attest,
    acme_managed_device
};

constexpr AppleAttestationSelection select_apple_attestation_selection(AppleAttestationPolicy policy, bool mdm_enrolled,
                                                                       bool acme_available)
{
    switch (policy)
    {
    case AppleAttestationPolicy::app_attest_only:
        return AppleAttestationSelection::app_attest;
    case AppleAttestationPolicy::mdm_only:
        return (mdm_enrolled && acme_available) ? AppleAttestationSelection::acme_managed_device
                                                : AppleAttestationSelection::none;
    case AppleAttestationPolicy::auto_select:
    default:
        return (mdm_enrolled && acme_available) ? AppleAttestationSelection::acme_managed_device
                                                : AppleAttestationSelection::app_attest;
    }
}

} // namespace mpss::impl::os
