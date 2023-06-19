/*

Copyright (c) 2018, Arvid Norberg
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

#ifndef NAT_HPP_INCLUDED
#define NAT_HPP_INCLUDED

#include "simulator/sink.hpp"
#include "simulator/simulator.hpp"
#include <string>

namespace sim {

namespace aux {
	struct packet;
}

	struct SIMULATOR_DECL nat : sink
	{
		nat(asio::ip::address external_addr);
		~nat() = default;

		void incoming_packet(aux::packet p) override;

		// used for visualization
		std::string label() const override;

	private:

		asio::ip::address m_external_addr;
	};

} // sim

#endif


