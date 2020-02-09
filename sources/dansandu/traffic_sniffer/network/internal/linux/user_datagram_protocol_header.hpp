#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/udp.h>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::user_datagram_protocol_header
{

Json deserializeUserDatagramProtocolHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd)
{
    constexpr int headerSize = sizeof(udphdr);

    auto layerSize = packetEnd - layerBegin;
    if (headerSize > layerSize)
        THROW(std::invalid_argument,
              "Could not extract user datagram protocol header from packet -- the header must have at least ",
              headerSize, " bytes instead of ", layerSize, " bytes");

    auto header = reinterpret_cast<const udphdr*>(layerBegin);
    auto json = std::map<std::string, Json>();
    json.emplace("sourcePort", Json::from<int>(ntohs(header->source)));
    json.emplace("destinationPort", Json::from<int>(ntohs(header->dest)));
    json.emplace("packetLength", Json::from<int>(layerSize));
    return Json::from<std::map<std::string, Json>>(std::move(json));
}

}
