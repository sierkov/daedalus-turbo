/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_NARROW_CAST_HPP
#define DAEDALUS_TURBO_NARROW_CAST_HPP

#include <limits>
#include <dt/error.hpp>

namespace daedalus_turbo {
    template<typename TO, typename FROM>
    constexpr TO narrow_cast(const FROM from)
    {
        if constexpr (std::numeric_limits<FROM>::is_signed == std::numeric_limits<TO>::is_signed) {
          if (from > std::numeric_limits<TO>::max()) [[unlikely]]
            throw error("can't convert {} {} to {}: the value is too big", typeid(FROM).name(), from, typeid(TO).name());
          if (from < std::numeric_limits<TO>::min()) [[unlikely]]
              throw error("can't convert {} {} to {}: the value is too small", typeid(FROM).name(), from, typeid(TO).name());
          return static_cast<TO>(from);
        }
        if constexpr (std::numeric_limits<FROM>::is_signed) {
            if (from < 0) [[unlikely]]
                throw error("can't convert {} {} to {}: the value is native", typeid(FROM).name(), from, typeid(TO).name());
            if (std::numeric_limits<FROM>::max() > std::numeric_limits<TO>::max()
                    && from > static_cast<FROM>(std::numeric_limits<TO>::max())) [[unlikely]]
                throw error("can't convert {} {} to {}: the value is too big", typeid(FROM).name(), from, typeid(TO).name());
            return static_cast<TO>(from);
        }
        if constexpr (std::numeric_limits<FROM>::digits > std::numeric_limits<TO>::digits) {
            if (from > static_cast<FROM>(std::numeric_limits<TO>::max())) [[unlikely]]
                throw error("can't convert {} {} to {}: the value is too big", typeid(FROM).name(), from, typeid(TO).name());
        } else {
            if (static_cast<TO>(from) > std::numeric_limits<TO>::max()) [[unlikely]]
                throw error("can't convert {} {} to {}: the value is too big", typeid(FROM).name(), from, typeid(TO).name());
        }
        return static_cast<TO>(from);
    }
}

#endif // !DAEDALUS_TURBO_NARROW_CAST_HPP
