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
#include <cstdio> // for printf
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

int num_sent = 0;
int num_received = 0;

void on_receive(boost::system::error_code const& ec, std::size_t bytes_transferred
	, udp::socket& s, udp::endpoint& ep)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	if (ec)
	{
		std::printf("[%4d] error while receiving: %s\n", millis, ec.message().c_str());
		return;
	}

	num_received += bytes_transferred;

	std::printf("[%4d] received %d bytes from %s\n", millis
		, int(bytes_transferred)
		, ep.address().to_string().c_str());

	if (bytes_transferred == 100 * 10) return;

	s.async_receive_from(asio::buffer(receive_buf
		, sizeof(receive_buf)), ep, std::bind(&on_receive, _1, _2
		, std::ref(s), std::ref(ep)));
}

}

TEST_CASE("send packet to udp socket", "[udp_socket]")
{
	default_config cfg;
	simulation sim(cfg);
	asio::io_context incoming_ios(sim, make_address_v4("40.30.20.10"));
	asio::io_context outgoing_ios(sim, make_address_v4("10.20.30.40"));

	udp::socket incoming(incoming_ios);
	udp::socket outgoing(outgoing_ios);

	boost::system::error_code ec;
	incoming.open(udp::v4(), ec);
	REQUIRE(!ec);
	incoming.bind(udp::endpoint(address(), 1337), ec);
	REQUIRE(!ec);

	outgoing.open(udp::v4(), ec);
	REQUIRE(!ec);

	udp::endpoint remote_endpoint;
	incoming.async_receive_from(asio::buffer(receive_buf,
			sizeof(receive_buf)), remote_endpoint, std::bind(&on_receive, _1, _2
			, std::ref(incoming), std::ref(remote_endpoint)));

	outgoing.non_blocking(true);
	REQUIRE(!ec);

	for (int i = 1; i < 10; ++i)
	{
		num_sent += outgoing.send_to(asio::buffer(send_buf, 100 * i)
			, udp::endpoint(make_address_v4("40.30.20.10"), 1337), 0, ec);
		REQUIRE(!ec);
	}

	sim.run();

	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	CHECK(num_sent == num_received);
	CHECK(num_sent == 100 * 45);
}

