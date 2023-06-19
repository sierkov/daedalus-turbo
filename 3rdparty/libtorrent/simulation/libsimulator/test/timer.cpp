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

using namespace sim::chrono;
using namespace sim::asio;
using sim::simulation;
using sim::default_config;
using namespace std::placeholders;

namespace {

	int counter = 0;
	const int expected_timestamps[] = {1000, 2000, 4000, 7000, 11000 };

	high_resolution_clock::time_point start;
}

void print_time(high_resolution_timer& timer
	, boost::system::error_code const& ec)
{
	using namespace sim::chrono;

	int millis = int(duration_cast<milliseconds>(high_resolution_clock::now() - start).count());

	std::printf("[%d] timer fired at: %d milliseconds. error: %s\n"
		, counter
		, millis
		, ec.message().c_str());

	if (ec)
	{
		CHECK(millis == 0);
		return;
	}

	CHECK(millis == expected_timestamps[counter]);

	++counter;
	if (counter < 5)
	{
		timer.expires_after(seconds(counter));
		timer.async_wait(std::bind(&print_time, std::ref(timer), _1));
	}
}

TEST_CASE("wait for timers", "[timer]")
{
	default_config cfg;
	simulation sim(cfg);
	io_context ios(sim, ip::make_address_v4("1.2.3.4"));
	high_resolution_timer timer(ios);

	start = high_resolution_clock::now();

	timer.expires_after(seconds(10));
	timer.async_wait(std::bind(&print_time, std::ref(timer), _1));

	timer.cancel();
	timer.expires_after(seconds(1));
	timer.async_wait(std::bind(&print_time, std::ref(timer), _1));

	sim.run();

	CHECK(counter == 5);
}

