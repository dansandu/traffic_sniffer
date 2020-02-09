#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::ethernet
{

const uint8_t* deserializeEthernetHeaderToJson(const uint8_t* packetBegin, const uint8_t* packetEnd,
                                               dansandu::jelly::json::Json& outputJson);

}
