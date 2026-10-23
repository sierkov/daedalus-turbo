#include <turbo/cbor/compare.hpp>
#include <turbo/common/test.hpp>

using namespace turbo;

suite cbor_compare_suite = [] {
    "cbor::compare"_test = [] {
        "first difference retains the nested path"_test = [] {
            const auto a = uint8_vector::from_hex("8282010203");
            const auto b = uint8_vector::from_hex("8282010405");
            const auto diff = cbor::compare(a, b, true);
            expect_equal(diff.size(), 1);
            expect(diff.at(0).to_string().starts_with("0.0.1:"));
            expect_equal(cbor::compare(a, b).size(), 2);
        };
        "non-myopic floats deliberately ignore the payload"_test = [] {
            for (const auto &[a, b]: {
                    std::pair { "81FA3F800000", "81FA40000000" },
                    std::pair { "81F93C00", "81F94000" } }) {
                expect(cbor::compare(uint8_vector::from_hex(a), uint8_vector::from_hex(b), true).empty());
            }
            expect(!cbor::compare(uint8_vector::from_hex("81F4"), uint8_vector::from_hex("81F5"), true).empty());
        };
        "trailing values and truncation"_test = [] {
            expect(!cbor::compare(uint8_vector::from_hex("8100"), uint8_vector::from_hex("810000"), true).empty());
            for (const bool first: { false, true }) {
                expect(throws([&] { cbor::compare(uint8_vector::from_hex("8100"), uint8_vector::from_hex("81"), first); }));
                // Identically truncated containers must not compare equal.
                for (const auto hex: { "81", "8200", "A1", "A100", "8181" }) {
                    const auto data = uint8_vector::from_hex(hex);
                    expect(throws([&] { cbor::compare(data, data, first); })) << hex;
                }
            }
        };
        "first missing or extra item does not decode the remaining tail"_test = [] {
            // The extra item begins a truncated byte string. Counting the tail
            // would throw instead of reporting the already-known difference.
            for (const auto &[shorter, longer]: {
                    std::pair { "80", "815A" },
                    std::pair { "A0", "A15A" },
                    std::pair { "00", "005A" } }) {
                const auto a = uint8_vector::from_hex(shorter), b = uint8_vector::from_hex(longer);
                const auto extra = cbor::compare(a, b, true), missing = cbor::compare(b, a, true);
                expect_equal(extra.size(), 1);
                expect_equal(missing.size(), 1);
                expect(extra.at(0).to_string().find("extra item") != std::string::npos);
                expect(missing.at(0).to_string().find("missing item") != std::string::npos);
                expect(throws([&] { cbor::compare(a, b); }));
            }
        };
    };
};
