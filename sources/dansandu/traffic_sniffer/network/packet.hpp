#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>
#include <vector>

namespace dansandu::traffic_sniffer::network::packet
{

const uint8_t* deserializePacketHeadersToJson(const std::vector<uint8_t>& packet,
                                              dansandu::jelly::json::Json& outputJson);

}
