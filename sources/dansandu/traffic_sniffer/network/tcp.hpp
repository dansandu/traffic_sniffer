#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::tcp
{

const uint8_t* deserializeTcpHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd,
                                          dansandu::jelly::json::Json& outputJson);

}
