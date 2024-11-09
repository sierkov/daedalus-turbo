/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
  * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/big_int.hpp>
#include <dt/plutus/types.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::plutus;

    using allocator_type = std::allocator<uint64_t>;
    using empty_type = boost::multiprecision::detail::empty_value<typename boost::multiprecision::backends::detail::rebind<boost::multiprecision::limb_type, allocator_type>::type>;

    using bint_backend_parent_type = boost::multiprecision::cpp_int_backend<
        0,
        0,
        boost::multiprecision::signed_magnitude,
        boost::multiprecision::checked,
        std::allocator<uint64_t>
    >;

    struct bint_backend_type: bint_backend_parent_type
    {
        using bint_backend_parent_type::bint_backend_parent_type;
    };

    struct bint_type {
        using value_type = boost::multiprecision::number<bint_backend_parent_type>;

        bint_type() =delete;

        bint_type(const bint_type &o): _ptr { o._ptr }
        {
        }

        bint_type(allocator &alloc): _ptr { alloc.make<value_type>() }
        {
        }

        bint_type(allocator &alloc, const auto &v): _ptr { alloc.make<value_type>(v) }
        {
        }

        bint_type &operator=(const bint_type &o)
        {
            _ptr = o._ptr;
            return *this;
        }

        bool operator==(const auto &o) const
        {
            return *_ptr == o;
        }

        const value_type &operator*() const
        {
            return *_ptr;
        }
    private:
        allocator::ptr_type<value_type> _ptr;
    };
}

suite big_int_suite = [] {
    "big_int"_test = [] {
        std::cerr << typeid(empty_type).name() << std::endl;
    };
};