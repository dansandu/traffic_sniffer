#pragma once

#include "dansandu/jelly/json.hpp"

#include <cstdint>

namespace dansandu::traffic_sniffer::network::transmission_control_protocol_header
{

dansandu::jelly::json::Json deserializeTransmissionControlProtocolHeaderToJson(const uint8_t* layerBegin,
                                                                               const uint8_t* packetEnd);

}
