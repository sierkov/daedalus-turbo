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

using namespace sim;
using namespace sim::asio::ip;
using namespace sim::chrono;
using sim::simulation;
using sim::default_config;
using namespace std::placeholders;

namespace {

char receive_buf[1000];
char send_buf[1000];

int num_ipv6 = 0;
int num_ipv4 = 0;

}

void on_receive(boost::system::error_code const& ec, std::size_t bytes_transferred
	, udp::socket& s)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	if (ec)
	{
		std::printf("[%4d] error while receiving: %s\n", millis, ec.message().c_str());
		return;
	}

	std::printf("[%4d] received packet on %s\n", millis,
		s.local_endpoint().address().to_string().c_str());

	if (s.local_endpoint().address().is_v4())
	{
		++num_ipv4;
	}
	else
	{
		++num_ipv6;
	}
}

TEST_CASE("one node can have multiple addresses (UDP)", "[multi-homed]")
{
	default_config cfg;
	simulation sim(cfg);

	// the machine receiving packets has two IP addresses
	asio::io_context incoming_ios(sim, {
		make_address_v4("40.30.20.10"),
		make_address_v6("ff::dead:beef:1337")} );
	asio::io_context outgoing_ios(sim, make_address_v4("10.20.30.40"));

	// we create two sockets for it, one for each interface
	udp::socket incoming_v4(incoming_ios);
	udp::socket incoming_v6(incoming_ios);
	udp::socket outgoing(outgoing_ios);

	boost::system::error_code ec;
	incoming_v4.open(udp::v4(), ec);
	REQUIRE(!ec);
	incoming_v4.bind(udp::endpoint(make_address_v4("40.30.20.10"), 1337), ec);
	REQUIRE(!ec);
	incoming_v4.async_receive(asio::buffer(receive_buf
		, sizeof(receive_buf)), std::bind(&on_receive, _1, _2
		, std::ref(incoming_v4)));

	incoming_v6.open(udp::v6(), ec);
	REQUIRE(!ec);
	incoming_v6.bind(udp::endpoint(make_address_v6("ff::dead:beef:1337"), 1337), ec);
	REQUIRE(!ec);
	incoming_v6.async_receive(asio::buffer(receive_buf
		, sizeof(receive_buf)), std::bind(&on_receive, _1, _2
		, std::ref(incoming_v6)));

	outgoing.open(udp::v4(), ec);
	REQUIRE(!ec);

	outgoing.non_blocking(true);
	REQUIRE(!ec);

	// send a packet to the IPv4 address
	outgoing.send_to(asio::buffer(send_buf, sizeof(send_buf))
		, udp::endpoint(make_address_v4("40.30.20.10"), 1337), 0, ec);
	REQUIRE(!ec);

	// and a packet to the IPv6 address
	outgoing.send_to(asio::buffer(send_buf, sizeof(send_buf))
		, udp::endpoint(make_address_v6("ff::dead:beef:1337"), 1337), 0, ec);
	REQUIRE(!ec);

	sim.run();

	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	CHECK(num_ipv4 == 1);
	CHECK(num_ipv6 == 1);
}

TEST_CASE("one node can have multiple addresses (TCP)", "[multi-homed]")
{
	default_config cfg;
	simulation sim(cfg);

	const unsigned short listen_port = 4242;

	// the machine receiving packets has two IP addresses
	asio::io_context incoming_ios(sim, {
		make_address_v4("40.30.20.10"),
		make_address_v6("ff::dead:beef:1337")} );

	// the machine sending packets has two IP addresses
	asio::io_context outgoing_ios(sim, {
		make_address_v4("10.20.30.40"),
		make_address_v6("ff::abad:cafe:1337")
	});

	// we create two acceptors for it, one for each interface
	asio::ip::tcp::acceptor incoming_v4(incoming_ios);
	asio::ip::tcp::acceptor incoming_v6(incoming_ios);

	tcp::socket outgoing_v4(outgoing_ios);
	tcp::socket outgoing_v6(outgoing_ios);

	boost::system::error_code ec;

	incoming_v4.open(tcp::v4(), ec);
	REQUIRE(!ec);
	incoming_v4.bind(tcp::endpoint(address_v4::any(), listen_port));
	REQUIRE(!ec);
	incoming_v4.listen();

	incoming_v6.open(tcp::v6(), ec);
	REQUIRE(!ec);
	incoming_v6.bind(tcp::endpoint(address_v6::any(), listen_port));
	REQUIRE(!ec);
	incoming_v6.listen();

	int num_incoming_v4 = 0;
	int num_incoming_v6 = 0;

	tcp::socket incoming_socket(incoming_ios);
	incoming_v4.async_accept(incoming_socket, [&] (boost::system::error_code ec) {
		REQUIRE(!ec);
		CHECK(incoming_socket.remote_endpoint().address() == make_address_v4("10.20.30.40"));
		num_incoming_v4++;
		incoming_socket.close();
	});

	incoming_v6.async_accept(incoming_socket, [&] (boost::system::error_code ec) {
		REQUIRE(!ec);
		CHECK(incoming_socket.remote_endpoint().address() == make_address_v6("ff::abad:cafe:1337"));
		num_incoming_v6++;
		incoming_socket.close();
	});

	// connect via ipv4
	outgoing_v4.open(tcp::v4(), ec);
	REQUIRE(!ec);
	auto endpoint_v4 = asio::ip::tcp::endpoint(asio::ip::make_address("40.30.20.10"), listen_port);
	outgoing_v4.async_connect(endpoint_v4, [] (boost::system::error_code ec) {
		REQUIRE(!ec);
	});
	sim.run();

	CHECK(num_incoming_v4 == 1);
	CHECK(num_incoming_v6 == 0);

	// connect via ipv6
	outgoing_v6.open(tcp::v6(), ec);
	REQUIRE(!ec);
	auto endpoint_v6 = asio::ip::tcp::endpoint(asio::ip::make_address("ff::dead:beef:1337"), listen_port);
	outgoing_v6.async_connect(endpoint_v6, [] (boost::system::error_code ec) {
		REQUIRE(!ec);
	});

	sim.run();

	CHECK(num_incoming_v4 == 1);
	CHECK(num_incoming_v6 == 1);
}

