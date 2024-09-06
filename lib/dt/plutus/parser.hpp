/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_SCRIPT_HPP
#define DAEDALUS_TURBO_PLUTUS_SCRIPT_HPP

#include <dt/blake2b.hpp>
#include <dt/cardano/type.hpp>
#include <dt/container.hpp>
#include <dt/util.hpp>
#include <dt/plutus/builtins.hpp>

namespace daedalus_turbo::plutus {
    struct script {
        explicit script(const buffer &data, bool cbor=true)
        {
            if (cbor) {
                auto cbor_item = cbor::parse(data);
                const auto &buf = cbor_item.buf();
                if (buf.size() > max_script_size)
                    throw error("script size of {} bytes exceeds the maximum allowed size of {}", buf.size(), max_script_size);
                _bytes = buf;
            } else {
                _bytes = data;
            }
            _decode_program();
        }

        std::string version() const
        {
            return fmt::format("{}.{}.{}", _ver_major, _ver_minor, _ver_patch);
        }

        const term &program() const
        {
            if (_term) [[likely]]
                return *_term;
            throw error("invalid plutus script!");
        }

        size_t max_vars() const
        {
            return _max_vars;
        }

        cardano::script_hash hash() const
        {
            return blake2b<cardano::script_hash>(_bytes);
        }
    private:
        static constexpr size_t max_script_size = 1 << 16;

        uint8_vector _bytes {};
        size_t _pos = 0;
        uint64_t _ver_major = 0;
        uint64_t _ver_minor = 0;
        uint64_t _ver_patch = 0;
        size_t _num_vars = 0;
        size_t _max_vars = 0;
        std::optional<term> _term {};

        inline bool _bit_at(size_t pos)
        {
            size_t byte_idx = pos >> 3;
            size_t bit_idx = pos & 0x7;
            if (byte_idx >= _bytes.size())
                throw error("out of data at bit {}", pos);
            return _bytes[byte_idx] & (1 << (7 - bit_idx));
        }

        inline bool _next_bit()
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

        cpp_int _decode_varlen_uint()
        {
            static constexpr size_t max_bits = 64 * 7;
            static constexpr size_t bits_per_block = 7;
            cpp_int val {};
            size_t base_idx = 0;
            for (;;) {
                bool last_block = !_next_bit();
                size_t max_idx = base_idx + bits_per_block - 1;
                for (size_t i = 0; i < bits_per_block; ++i) {
                    const auto bit = _next_bit();
                    if (bit) {
                        if (max_idx - i >= max_bits)
                            throw error("integers larger than {} bits are not allowed", max_bits);
                        val |= cpp_int { 1 } << (max_idx - i);
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
            return std::string { reinterpret_cast<const char *>(bytes.data()), bytes.size() };
        }

        uint8_vector _decode_data()
        {
            return _decode_bytestring();
        }

        constant_type _decode_type_application(std::vector<type_tag>::iterator &it, const std::vector<type_tag>::iterator end)
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

        constant_type _decode_constant_type(std::vector<type_tag>::iterator &it, const std::vector<type_tag>::iterator end)
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
                case type_tag::integer: return constant { typ, { _decode_integer() } };
                case type_tag::bytestring: return constant { typ, { _decode_bytestring() } };
                case type_tag::string: return constant { typ, { _decode_string() } };
                case type_tag::unit: return constant { typ };
                case type_tag::boolean: return constant { typ, { _decode_boolean() } };
                case type_tag::data: return constant { typ, { _decode_data() } };
                case type_tag::list: {
                    constant_list vals {};
                    _decode_list([&] {
                        vals.emplace_back(_decode_constant_val(typ.nested.at(0)));
                    });
                    return { typ, { std::move(vals) } };
                }
                case type_tag::pair: {
                    constant_list vals {};
                    vals.emplace_back(_decode_constant_val(typ.nested.at(0)));
                    vals.emplace_back(_decode_constant_val(typ.nested.at(1)));
                    return { typ, { std::move(vals) } };
                }
                default: throw error("unsupported constant type: {}", static_cast<int>(typ.typ));
            }
        }

        constant_list _decode_constant()
        {
            std::vector<type_tag> type_list {};
            for (;;) {
                if (!_next_bit())
                    break;
                type_list.emplace_back(static_cast<type_tag>(_decode_fixed_uint<uint8_t>(4)));
            }
            if (type_list.empty())
                throw error("an empty constant type!");
            //logger::info("constant types: {}", type_list);
            constant_list constants {};
            for (auto it = type_list.begin(), end = type_list.end(); it != end; ++it) {
                const auto typ = _decode_constant_type(it, end);
                constants.emplace_back(_decode_constant_val(typ));
            }
            return constants;
        }

        builtin _decode_builtin()
        {
            return builtin { static_cast<builtin_tag>(_decode_fixed_uint<uint8_t>(7)) };
        }

        variable _decode_variable()
        {
            const auto rel_idx = static_cast<size_t>(_decode_varlen_uint());
            if (rel_idx > _num_vars)
                throw daedalus_turbo::error("De Bruin index is out of range: {} num_vars: {}", rel_idx, _num_vars);
            return variable { _num_vars - rel_idx };
        }

        delay _decode_delay()
        {
            return delay { term::make_ptr(_decode_term()) };
        }

        lambda _decode_lambda()
        {
            lambda l { _num_vars++, term::make_ptr(_decode_term()) };
            if (_num_vars > _max_vars)
                _max_vars = _num_vars;
            --_num_vars;
            return l;
        }

        apply _decode_apply()
        {
            return apply { term::make_ptr(_decode_term()), term::make_ptr(_decode_term()) };
        }

        force _decode_force()
        {
            return force { term::make_ptr(_decode_term()) };
        }

        failure _decode_error()
        {
            return failure {};
        }

        term _decode_term()
        {
            //const auto start_pos = _pos;
            const auto typ = static_cast<term_tag>(_decode_fixed_uint<uint8_t>(4));
            //logger::info("{}: started decoding {}", start_pos, typ);
            term t;
            switch (typ) {
                case term_tag::variable: t = term { typ, _decode_variable() }; break;
                case term_tag::delay: t = term { typ, _decode_delay() }; break;
                case term_tag::lambda: t = term { typ, _decode_lambda() }; break;
                case term_tag::apply: t = term { typ, _decode_apply() }; break;
                case term_tag::constant: t = term { typ, _decode_constant() }; break;
                case term_tag::force: t = term { typ, _decode_force() }; break;
                case term_tag::error: t = term { typ, _decode_error() }; break;
                case term_tag::builtin: t = term { typ, _decode_builtin() }; break;
                default:
                    throw error("unexpected term: {}", static_cast<int>(typ));
            }
            //logger::info("[{}:{}): completed decoding {}", start_pos, _pos, t);
            return t;
        }

        void _decode_program()
        {
            _ver_major = static_cast<uint64_t>(_decode_varlen_uint());
            _ver_minor = static_cast<uint64_t>(_decode_varlen_uint());
            _ver_patch = static_cast<uint64_t>(_decode_varlen_uint());
            _term = _decode_term();
            //_consume_padding();
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
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::script>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(program {} {})", v.version(), v.program());
        }
    };
}

#endif // !DAEDALUS_TURBO_PLUTUS_SCRIPT_HPP