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
char send_buffer[10000];
char recv_buffer[10000];
int num_received = 0;
int num_sent = 0;

void on_sent(boost::system::error_code const& ec, std::size_t bytes_transferred
	, ip::tcp::socket& sock)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
	if (ec)
	{
		std::printf("[%4d] send error %s\n", millis, ec.message().c_str());
		return;
	}

	num_sent += bytes_transferred;

	std::printf("[%4d] sent %d bytes\n", millis, int(bytes_transferred));
	std::printf("closing\n");
	sock.close();
}

void on_receive(boost::system::error_code const& ec
	, std::size_t bytes_transferred, ip::tcp::socket& sock)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
	if (ec)
	{
		std::printf("[%4d] receive error %s\n", millis, ec.message().c_str());
		return;
	}

	num_received += bytes_transferred;

	std::printf("[%4d] received %d bytes\n", millis, int(bytes_transferred));

	sock.async_read_some(sim::asio::buffer(recv_buffer, sizeof(recv_buffer))
		, std::bind(&on_receive, _1, _2, std::ref(sock)));
}

void incoming_connection(boost::system::error_code const& ec
	, ip::tcp::socket& sock, ip::tcp::endpoint const& ep)
{
	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());
	if (ec)
	{
		std::printf("[%4d] error while accepting connection: %s\n"
			, millis, ec.message().c_str());
		return;
	}

	boost::system::error_code err;
	ip::tcp::endpoint remote_endpoint = sock.remote_endpoint(err);
	REQUIRE(!ec);
	ip::tcp::endpoint local_endpoint = sock.local_endpoint(err);
	REQUIRE(!ec);
	std::printf("[%4d] received incoming connection from: %s:%d. local endpoint: %s:%d\n"
		, millis, ep.address().to_string().c_str(), ep.port()
		, local_endpoint.address().to_string().c_str(), local_endpoint.port());
	CHECK(local_endpoint.port() == 1337);
	CHECK(local_endpoint.address().to_string() == "40.30.20.10");
	CHECK(remote_endpoint.port() != 0);
	CHECK(remote_endpoint.address().to_string() == "10.20.30.40");

	sock.async_read_some(sim::asio::buffer(recv_buffer, sizeof(recv_buffer))
		, std::bind(&on_receive, _1, _2, std::ref(sock)));
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

	boost::system::error_code err;
	ip::tcp::endpoint remote_endpoint = sock.remote_endpoint(err);
	REQUIRE(!ec);
	ip::tcp::endpoint local_endpoint = sock.local_endpoint(err);
	REQUIRE(!ec);

	std::printf("[%4d] made outgoing connection to: %s:%d. local endpoint: %s:%d\n"
		, millis
		, remote_endpoint.address().to_string().c_str(), remote_endpoint.port()
		, local_endpoint.address().to_string().c_str(), local_endpoint.port());

	CHECK(remote_endpoint.port() == 1337);
	CHECK(remote_endpoint.address().to_string() == "40.30.20.10");
	CHECK(local_endpoint.port() != 0);
	CHECK(local_endpoint.address().to_string() == "10.20.30.40");

	std::printf("sending %d bytes\n", int(sizeof(send_buffer)));
	sock.async_write_some(sim::asio::buffer(send_buffer, sizeof(send_buffer))
		, std::bind(&on_sent, _1, _2, std::ref(sock)));
}

}

TEST_CASE("accept incoming connection on acceptor socket", "[acceptor]")
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
	REQUIRE(!ec);
	listener.bind(ip::tcp::endpoint(ip::address(), 1337), ec);
	REQUIRE(!ec);
	listener.listen(10, ec);
	REQUIRE(!ec);

	ip::tcp::socket incoming(incoming_ios);
	ip::tcp::endpoint remote_endpoint;
	listener.async_accept(incoming, remote_endpoint
		, std::bind(&incoming_connection, _1, std::ref(incoming)
		, std::cref(remote_endpoint)));

	dump_network_graph(sim, "accept.dot");

	std::printf("[%4d] connecting\n", millis);
	ip::tcp::socket outgoing(outgoing_ios);
	outgoing.open(ip::tcp::v4(), ec);
	REQUIRE(!ec);
	outgoing.async_connect(ip::tcp::endpoint(ip::make_address("40.30.20.10")
		, 1337), std::bind(&on_connected, _1, std::ref(outgoing)));

	sim.run();

	millis = int(duration_cast<milliseconds>(high_resolution_clock::now()
		.time_since_epoch()).count());

	CHECK(num_received == num_sent);
	CHECK(num_received > 0);
}

