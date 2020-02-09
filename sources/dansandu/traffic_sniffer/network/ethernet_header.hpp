#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::ethernet_header
{

dansandu::jelly::json::Json deserializeEthernetHeaderToJson(const uint8_t* packetBegin, const uint8_t* packetEnd);

}
