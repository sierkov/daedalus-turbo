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

#ifndef SIMULATOR_MALLOCATOR_HPP_INCLUDED
#define SIMULATOR_MALLOCATOR_HPP_INCLUDED

namespace sim
{
namespace aux
{
	struct channel;
	struct packet;
	struct pcap;

	template <typename T>
	struct mallocator
	{
		template <typename U>
		friend struct mallocator;

		using value_type = T;
		using pointer = T*;
		using const_pointer = T const*;
		using reference = T&;
		using const_reference = T const&;
		using size_type = std::size_t;
		using difference_type = std::ptrdiff_t;

		template <class U>
		struct rebind {
			using other = mallocator<U>;
		};

		mallocator() = default;
		template <typename U>
		mallocator(mallocator<U> const&) {}

		T* allocate(std::size_t size)
		{ return reinterpret_cast<T*>(std::malloc(size * sizeof(T))); }

		void deallocate(T* ptr) { std::free(ptr); }
		void deallocate(T* ptr, std::size_t) { std::free(ptr); }

		void destroy(pointer p) { p->~T(); }
		void construct(pointer p, T&& value) { new (p) T(std::move(value)); }

		bool operator==(mallocator const&) const { return true; }
		bool operator!=(mallocator const&) const { return false; }
	};
} // aux
} // sim

#endif // SIMULATOR_MALLOCATOR_HPP_INCLUDED

