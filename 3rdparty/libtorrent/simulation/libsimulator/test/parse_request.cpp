/*

Copyright (c) 2017, Arvid Norberg
All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "simulator/simulator.hpp"
#include <functional>

#include "catch.hpp"
#include "simulator/http_server.hpp" // for parse_request

#ifdef __GNUC__
// for CATCH's CHECK macro
#pragma GCC diagnostic ignored "-Wparentheses"
#endif

TEST_CASE("parse GET request", "[parse_request]")
{
	auto str = "GET /foo/bar?x=4 HTTP/1.1\r\n\r\n";
	sim::http_request req = sim::parse_request(str, std::strlen(str));
	CHECK(req.method == "GET");
	CHECK(req.req == "/foo/bar?x=4");
	CHECK(req.path == "/foo/bar");
	CHECK(req.headers.empty());
}

TEST_CASE("request path is normalized (no leading slash)", "[parse_request]")
{
	auto str = "GET foo/bar HTTP/1.1\r\n\r\n";
	sim::http_request req = sim::parse_request(str, std::strlen(str));
	CHECK(req.path == "/foo/bar");
}

TEST_CASE("request path is normalized (..)", "[parse_request]")
{
	auto str = "GET /foo/../foo/bar HTTP/1.1\r\n\r\n";
	sim::http_request req = sim::parse_request(str, std::strlen(str));
	CHECK(req.path == "/foo/bar");
}

TEST_CASE("parse CONNECT request", "[parse_request]")
{
	auto str = "CONNECT 192.168.0.1:8888 HTTP/1.1\r\n\r\n";
	sim::http_request req = sim::parse_request(str, std::strlen(str));
	CHECK(req.method == "CONNECT");
	CHECK(req.req == "192.168.0.1:8888");
	CHECK(req.path == "192.168.0.1:8888");
	CHECK(req.headers.empty());
}

TEST_CASE("headers are parsed", "[parse_request]")
{
	auto str = "GET / HTTP/1.1\r\nX-Foo: Bar\r\n\r\n";
	sim::http_request req = sim::parse_request(str, std::strlen(str));
	CHECK(!req.headers.empty());
	CHECK(req.headers["x-foo"] == "Bar");
}

TEST_CASE("invalid formed request throws parse exception", "[parse_request]")
{
	auto str = "INVALID";
	REQUIRE_THROWS_WITH(sim::parse_request(str, std::strlen(str)), Catch::Contains("parse failed"));
}
