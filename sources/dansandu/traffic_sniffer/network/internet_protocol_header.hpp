#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::internet_protocol_header
{

dansandu::jelly::json::Json deserializeInternetProtocolHeaderToJson(const uint8_t* layerBegin,
                                                                    const uint8_t* packetEnd);

}
