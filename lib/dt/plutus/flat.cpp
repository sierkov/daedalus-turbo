/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/blake2b.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/cardano/types.hpp>
#include <dt/container.hpp>
#include <dt/util.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/flat.hpp>

namespace daedalus_turbo::plutus::flat {
    struct script::impl {
        impl(uint8_vector &&bytes, const bool cbor):
            _bytes_raw { std::move(bytes) },
            _bytes { cbor ? _extract_cbor_data(_bytes_raw) : _bytes_raw.span() }
        {
            _decode_program();
            if (!_term || !_ver) [[unlikely]]
                throw error("the script instance has been incorrectly initialized!");
        }

        plutus::version version() const
        {
            return *_ver;
        }

        term_ptr program() const
        {
            return _term;
        }
    private:
        static constexpr size_t max_script_size = 1 << 16;

        uint8_vector _bytes_raw;
        buffer _bytes { _bytes_raw };
        size_t _pos = 0;
        size_t _num_vars = 0;
        std::optional<plutus::version> _ver;
        term_ptr _term;

        static buffer _extract_cbor_data(const buffer bytes)
        {
            const auto cbor_item = cbor::zero::parse(bytes);
            const auto buf = cbor_item.bytes();
            if (buf.size() <= max_script_size) [[likely]]
                return buf;
            throw error("script size of {} bytes exceeds the maximum allowed size of {}", buf.size(), max_script_size);
        }

        bool _bit_at(size_t pos)
        {
            size_t byte_idx = pos >> 3;
            size_t bit_idx = pos & 0x7;
            if (byte_idx >= _bytes.size())
                throw error("out of data at bit {}", pos);
            return _bytes[byte_idx] & (1 << (7 - bit_idx));
        }

        bool _next_bit()
        {
            return _bit_at(_pos++);
        }

        template<std::unsigned_integral N>
        N _decode_fixed_uint(const size_t num_bits=sizeof(N) * 8)
        {
            static_assert(sizeof(N) <= sizeof(unsigned long long));
            const size_t max_bit_idx = num_bits - 1;
            N val {};
            for (size_t i = 0; i < num_bits; ++i) {
                if (_next_bit())
                    val |= 1ULL << (max_bit_idx - i);
            }
            return val;
        }

        static const vector<cpp_int> &_powers_of_two(const size_t max_pow)
        {
            static vector<cpp_int> powers {};
            if (powers.size() <= max_pow) [[unlikely]] {
                powers.reserve(max_pow + 1);
                while (powers.size() <= max_pow)
                    powers.emplace_back(boost::multiprecision::pow(cpp_int { 2 }, powers.size()));
            }
            return powers;
        }

        cpp_int _decode_varlen_uint()
        {
            static constexpr size_t max_bits = 64 * 7;
            static constexpr size_t bits_per_block = 7;
            static const auto &pow2 = _powers_of_two(max_bits);
            cpp_int val {};
            size_t base_idx = 0;
            for (;;) {
                bool last_block = !_next_bit();
                size_t max_idx = base_idx + bits_per_block - 1;
                for (size_t i = 0, bit_pos = max_idx; i < bits_per_block; ++i, --bit_pos) {
                    if (const auto bit = _next_bit(); bit) {
                        if (bit_pos >= max_bits) [[unlikely]]
                            throw error("integers larger than {} bits are not allowed", max_bits);
                        val |= pow2[bit_pos];
                    }
                }
                if (last_block)
                    break;
                base_idx += 7;
            }
            return val;
        }

        cpp_int _decode_integer()
        {
            const cpp_int u = _decode_varlen_uint();
            cpp_int i = u >> 1;
            if (u & 1) {
                i = -(i + 1);
            }
            return i;
        }

        bool _decode_boolean()
        {
            return _next_bit();
        }

        void _decode_list(const std::function<void()> &observer)
        {
            for (;;) {
                if (!_next_bit())
                    break;
                observer();
            }
        }

        void _consume_padding()
        {
            const auto start_pos = _pos;
            while (!_next_bit()) {
                // do nothing
            }
            if (_pos % 8)
                throw error("consume_padding: didn't finish on a byte boundary at bit {}!", start_pos);
            if (_pos - start_pos > 8)
                throw error("consume_padding: took more than 8 bits of data at bit {}!", start_pos);
        }

        uint8_vector _decode_bytestring()
        {
            _consume_padding();
            uint8_vector data {};
            for (;;) {
                const size_t chunk_size = _decode_fixed_uint<uint8_t>();
                if (!chunk_size)
                    break;
                size_t data_idx = data.size();
                data.resize(data.size() + chunk_size);
                size_t byte_idx = _pos >> 3;
                if (byte_idx + chunk_size > _bytes.size())
                    throw error("insufficient data for a bytestring of size {} at bit position: {}", chunk_size, _pos);
                memcpy(data.data() + data_idx, _bytes.data() + byte_idx, chunk_size);
                _pos += chunk_size * 8;
            }
            return data;
        }

        std::string _decode_string()
        {
            auto bytes = _decode_bytestring();
            return { reinterpret_cast<const char *>(bytes.data()), bytes.size() };
        }

        data _decode_data()
        {
            const auto bytes = _decode_bytestring();
            return data::from_cbor(bytes);
        }

        constant_type _decode_type_application(std::vector<type_tag>::iterator it, const std::vector<type_tag>::iterator end)
        {
            if (++it == end)
                throw error("type list too short!");
            switch (*it) {
                case type_tag::list: {
                    if (++it == end)
                        throw error("type list too short!");
                    constant_type_list nested {};
                    nested.emplace_back(_decode_constant_type(it, end));
                    return { type_tag::list, { std::move(nested) } };
                }
                case type_tag::pair: {
                    if (++it == end)
                        throw error("type list too short!");
                    constant_type_list nested {};
                    nested.emplace_back(_decode_constant_type(it, end));
                    if (++it == end)
                        throw error("type list too short!");
                    nested.emplace_back(_decode_constant_type(it, end));
                    return { type_tag::pair, { std::move(nested) } };
                }
                case type_tag::application:
                    return _decode_type_application(it, end);
                default:
                    throw error("unsupported container type for an application: {}", *it);
            }
        }

        constant_type _decode_constant_type(std::vector<type_tag>::iterator it, const std::vector<type_tag>::iterator end)
        {
            const auto &typ = *it;
            switch (typ) {
                case type_tag::integer:
                case type_tag::bytestring:
                case type_tag::string:
                case type_tag::unit:
                case type_tag::boolean:
                case type_tag::data:
                    return { typ };
                case type_tag::list:
                case type_tag::pair:
                    throw error("list and pair types are supported only within a type application");
                case type_tag::application:
                    return _decode_type_application(it, end);
                default: throw error("unsupported constant type: {}", static_cast<int>(typ));
            }
        }

        constant _decode_constant_val(const constant_type &typ)
        {
            switch (typ.typ) {
                case type_tag::integer: return { _decode_integer() };
                case type_tag::bytestring: return { _decode_bytestring() };
                case type_tag::string: return { _decode_string() };
                case type_tag::unit: return { std::monostate{} };
                case type_tag::boolean: return { _decode_boolean() };
                case type_tag::data: return { _decode_data() };
                case type_tag::list: {
                    auto cl = constant_list::make_empty(typ.nested.at(0));
                    _decode_list([&] {
                        cl.vals.emplace_back(_decode_constant_val(typ.nested.at(0)));
                    });
                    return { cl };
                }
                case type_tag::pair: {
                    auto fst = _decode_constant_val(typ.nested.at(0));
                    auto snd = _decode_constant_val(typ.nested.at(1));
                    return { constant_pair { std::move(fst), std::move(snd) } };
                }
                default: throw error("unsupported constant type: {}", static_cast<int>(typ.typ));
            }
        }

        constant _decode_constant()
        {
            vector<type_tag> types {};
            for (;;) {
                if (!_next_bit())
                    break;
                types.emplace_back(static_cast<type_tag>(_decode_fixed_uint<uint8_t>(4)));
            }
            if (types.empty())
                throw error("no type is defined at pos: {}!", _pos);
            auto typ = _decode_constant_type(types.begin(), types.end());
            return _decode_constant_val(std::move(typ));
        }

        t_builtin _decode_builtin()
        {
            return { static_cast<builtin_tag>(_decode_fixed_uint<uint8_t>(7)) };
        }

        variable _decode_variable()
        {
            const auto rel_idx = static_cast<size_t>(_decode_varlen_uint());
            if (rel_idx <= _num_vars) [[likely]]
                return { fmt::format("v{}", _num_vars - rel_idx) };
            throw daedalus_turbo::error("De Bruijn index is out of range: {} num_vars: {}", rel_idx, _num_vars);
        }

        t_delay _decode_delay()
        {
            return { term::make_ptr(_decode_term()) };
        }

        t_lambda _decode_lambda()
        {
            auto name = fmt::format("v{}", _num_vars++);
            auto body = term::make_ptr(_decode_term());
            --_num_vars;
            return { std::move(name), std::move(body) };
        }

        apply _decode_apply()
        {
            return { term::make_ptr(_decode_term()), term::make_ptr(_decode_term()) };
        }

        force _decode_force()
        {
            return { term::make_ptr(_decode_term()) };
        }

        failure _decode_error()
        {
            return {};
        }

        term _decode_term()
        {
            const auto typ = static_cast<term_tag>(_decode_fixed_uint<uint8_t>(4));
            switch (typ) {
                case term_tag::variable: return { _decode_variable() };
                case term_tag::delay: return { _decode_delay() };
                case term_tag::lambda: return { _decode_lambda() };
                case term_tag::apply: return { _decode_apply() };
                case term_tag::constant: return { _decode_constant() };
                case term_tag::force: return { _decode_force() };
                case term_tag::error: return { _decode_error() };
                case term_tag::builtin: return { _decode_builtin() };
                default: throw error("unexpected term: {}", static_cast<int>(typ));
            }
        }

        void _decode_program()
        {
            const auto major = static_cast<uint64_t>(_decode_varlen_uint());
            const auto minor = static_cast<uint64_t>(_decode_varlen_uint());
            const auto patch = static_cast<uint64_t>(_decode_varlen_uint());
            _ver.emplace(major, minor, patch);
            _term = term::make_ptr(_decode_term());
        }

        static void _pad(vector<bool> &bits)
        {
            size_t pad_bits = 0;
            switch (bits.size() % 8) {
                case 0: pad_bits = 7; break;
                case 1: pad_bits = 6; break;
                case 2: pad_bits = 5; break;
                case 3: pad_bits = 4; break;
                case 4: pad_bits = 3; break;
                case 5: pad_bits = 2; break;
                case 6: pad_bits = 1; break;
                case 7: pad_bits = 0; break;
                default: std::unreachable();
            }
            for (; pad_bits > 0; --pad_bits)
                bits.emplace_back(false);
            bits.emplace_back(true);
            if (bits.size() % 8 != 0)
                throw error("failed to pad the bit string to a byte boundary: {}!", bits.size());
        }
    };

    script::script(uint8_vector &&bytes, const bool cbor):
            _impl { std::make_unique<impl>(std::move(bytes), cbor) }
    {
    }

    script::script(const buffer bytes, const bool cbor):
        script { uint8_vector { bytes }, cbor }
    {
    }

    script::~script() =default;

    version script::version() const
    {
        return _impl->version();
    }
    term_ptr script::program() const
    {
        return _impl->program();
    }
}
