#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::user_datagram_protocol_header
{

dansandu::jelly::json::Json deserializeUserDatagramProtocolHeaderToJson(const uint8_t* layerBegin,
                                                                        const uint8_t* packetEnd);

}
