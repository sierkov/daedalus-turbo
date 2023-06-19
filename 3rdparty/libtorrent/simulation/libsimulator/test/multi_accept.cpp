/*

Copyright (c) 2015, Arvid Norberg
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

#ifdef __GNUC__
// for CATCH's CHECK macro
#pragma GCC diagnostic ignored "-Wparentheses"
#endif

using namespace sim::asio;
using namespace sim::chrono;
using sim::simulation;
using sim::default_config;
using namespace std::placeholders;

namespace {

int num_incoming = 0;
int num_connected = 0;

int counter = 0;

void incoming_connection(boost::system::error_code const& ec
	, ip::tcp::socket& sock, ip::tcp::acceptor& listener)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
	if (ec)
	{
		std::printf("[%4d] error while accepting connection: %s\n"
			, millis, ec.message().c_str());
		return;
	}

	++num_incoming;

	std::printf("[%4d] received incoming connection\n", millis);
	sock.close();

	listener.async_accept(sock, std::bind(&incoming_connection
		, _1, std::ref(sock), std::ref(listener)));
}

void on_connected(boost::system::error_code const& ec
	, ip::tcp::socket& sock)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
	if (ec)
	{
		std::printf("[%4d] error while connecting: %s\n", millis, ec.message().c_str());
		return;
	}

	++num_connected;

	std::printf("[%4d] made outgoing connection\n", millis);
	sock.close();

	if (++counter > 5) return;

	boost::system::error_code err;
	sock.open(ip::tcp::v4(), err);
	if (err) std::printf("[%4d] open failed: %s\n", millis, err.message().c_str());
	sock.async_connect(ip::tcp::endpoint(ip::make_address("40.30.20.10")
		, 1337), std::bind(&on_connected, _1, std::ref(sock)));
}

}

TEST_CASE("accept a connection multiple times on the same socket", "[accept]")
{
	default_config cfg;
	simulation sim(cfg);
	io_context incoming_ios(sim, ip::make_address_v4("40.30.20.10"));
	io_context outgoing_ios(sim, ip::make_address_v4("10.20.30.40"));
	ip::tcp::acceptor listener(incoming_ios);

	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	boost::system::error_code ec;
	listener.open(ip::tcp::v4(), ec);
	if (ec) std::printf("[%4d] open failed: %s\n", millis, ec.message().c_str());
	listener.bind(ip::tcp::endpoint(ip::address(), 1337), ec);
	if (ec) std::printf("[%4d] bind failed: %s\n", millis, ec.message().c_str());
	listener.listen(10, ec);
	if (ec) std::printf("[%4d] listen failed: %s\n", millis, ec.message().c_str());

	ip::tcp::socket incoming(incoming_ios);
	listener.async_accept(incoming
		, std::bind(&incoming_connection, _1, std::ref(incoming)
		, std::ref(listener)));

	std::printf("[%4d] connecting\n", millis);
	ip::tcp::socket outgoing(outgoing_ios);
	outgoing.open(ip::tcp::v4(), ec);
	if (ec) std::printf("[%4d] open failed: %s\n", millis, ec.message().c_str());
	outgoing.async_connect(ip::tcp::endpoint(ip::make_address("40.30.20.10")
		, 1337), std::bind(&on_connected, _1, std::ref(outgoing)));

	sim.run();

	CHECK(num_incoming == 6);
	CHECK(num_connected == 6);

	millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
}

