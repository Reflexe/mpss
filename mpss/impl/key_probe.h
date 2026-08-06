// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

namespace mpss::impl
{

/**
 * @brief Outcome of looking up a key by name in a backing store.
 *
 * A lookup has three outcomes, not two. Collapsing @ref not_found and @ref operational_error into a
 * single "no key" answer makes a store that could not be queried indistinguishable from a store that
 * was queried and holds nothing. Backends that report this distinction let creation refuse to proceed
 * when the store could not be read, because a key of the same name may already be present.
 */
enum class KeyProbeStatus
{
    /** @brief The store was queried and holds a key with this name. */
    found,

    /** @brief The store was queried and holds no key with this name. */
    not_found,

    /**
     * @brief The store could not be queried, so the presence of the key is unknown.
     *
     * The last error describes the failure.
     */
    operational_error
};

/**
 * @brief A @ref KeyProbeStatus paired with whatever the backend recovered about the key.
 *
 * @p value is meaningful only when @p status is KeyProbeStatus::found.
 *
 * @tparam T Backend-specific description of the key that was found.
 */
template <typename T> struct KeyProbeResult
{
    /** @brief Whether the key was found, absent, or could not be determined. */
    KeyProbeStatus status;

    /** @brief What the backend recovered about the key. Only valid when @p status is found. */
    T value;
};

} // namespace mpss::impl
