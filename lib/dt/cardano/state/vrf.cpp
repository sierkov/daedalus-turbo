/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cardano/state/vrf.hpp>
#include <dt/zpp.hpp>

void daedalus_turbo::cardano::state::vrf::load(const std::string &path)
{
    zpp::load(*this, path);
}

void daedalus_turbo::cardano::state::vrf::save(const std::string &path) const
{
    zpp::save(path, *this);
}