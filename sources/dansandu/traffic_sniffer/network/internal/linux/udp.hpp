#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/udp.h>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::udp
{

const uint8_t* deserializeUdpHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd, Json& outputJson)
{
    constexpr int headerSize = sizeof(udphdr);

    auto layerSize = packetEnd - layerBegin;
    if (headerSize > layerSize)
        THROW(std::invalid_argument,
              "Could not extract user datagram protocol header from packet -- the header must have at least ",
              headerSize, " bytes instead of ", layerSize, " bytes");

    auto header = reinterpret_cast<const udphdr*>(layerBegin);
    auto& map = outputJson.get<std::map<std::string, Json>>();
    map.emplace("sourcePort", static_cast<int>(ntohs(header->source)));
    map.emplace("destinationPort", static_cast<int>(ntohs(header->dest)));
    map.emplace("udpLength", static_cast<int>(ntohs(header->len)));
    return layerBegin + headerSize;
}

}
