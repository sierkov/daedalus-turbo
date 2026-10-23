#pragma once

#include <cstring>

namespace hash_library_detail
{
  template <typename T>
  inline T loadUnaligned(const void* data) noexcept
  {
    T value;
    std::memcpy(&value, data, sizeof(value));
    return value;
  }
}
