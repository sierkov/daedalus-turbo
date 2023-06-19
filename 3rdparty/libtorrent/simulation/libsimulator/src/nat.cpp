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

#include "simulator/nat.hpp"
#include "simulator/simulator.hpp"
#include "simulator/packet.hpp"
#include <string>

namespace sim {

	nat::nat(asio::ip::address external_addr) : m_external_addr(external_addr) {}

	void nat::incoming_packet(aux::packet p)
	{
		// unconditionally replacing the "from" address is fine because of our
		// simplified network model where the two paths of a connection are set up
		// independently, and we can set up the nat hop only on the outgoing path
		p.from.address(m_external_addr);
		if (p.channel) {
			p.channel->visible_ep[0].address(m_external_addr);
		}
		forward_packet(std::move(p));
	}

	// used for visualization
	std::string nat::label() const
	{
		return std::string("NAT [") + m_external_addr.to_string() + "]";
	}

} // sim

