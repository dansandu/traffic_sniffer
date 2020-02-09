#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::udp
{

const uint8_t* deserializeUdpHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd,
                                          dansandu::jelly::json::Json& outputJson);

}
