// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <utility>

namespace mpss::utils
{

// Move-only owner for a resource handle of type T, released with Deleter{} on destruction or reset.
// Invalid is the empty/unset value (default T{}); a handle equal to Invalid is never released.
// Unlike std::unique_ptr this can own non-pointer handles, such as the integer handles used by
// Win32/NCrypt.
template <typename T, typename Deleter, T Invalid = T{}>
class UniqueResource
{
  public:
    UniqueResource() = default;
    explicit UniqueResource(T value) noexcept : value_{value}
    {
    }

    UniqueResource(UniqueResource &&other) noexcept : value_{std::exchange(other.value_, Invalid)}
    {
    }
    UniqueResource &operator=(UniqueResource &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            value_ = std::exchange(other.value_, Invalid);
        }
        return *this;
    }

    UniqueResource(const UniqueResource &) = delete;
    UniqueResource &operator=(const UniqueResource &) = delete;

    ~UniqueResource()
    {
        reset();
    }

    [[nodiscard]] T get() const noexcept
    {
        return value_;
    }

    // Relinquishes ownership without releasing: returns the value and empties the wrapper. Used when
    // another call (e.g. NCryptDeleteKey) has already taken ownership of the underlying resource.
    T release() noexcept
    {
        return std::exchange(value_, Invalid);
    }

    explicit operator bool() const noexcept
    {
        return Invalid != value_;
    }

    // Releases any current value, then returns its address for an out-parameter API (e.g. an
    // open/create call); the wrapper owns whatever the call stores. Mirrors std::out_ptr (C++23).
    T *out_ptr() noexcept
    {
        reset();
        return &value_;
    }

    void reset() noexcept
    {
        if (Invalid != value_)
        {
            Deleter{}(value_);
            value_ = Invalid;
        }
    }

  private:
    T value_ = Invalid;
};

} // namespace mpss::utils
