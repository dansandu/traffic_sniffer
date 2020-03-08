#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/if_ether.h>
#include <map>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::ethernet
{

static std::string getMacAddress(const uint8_t* field)
{
    constexpr auto bufferSize = 25;
    char buffer[bufferSize];
    snprintf(buffer, bufferSize, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", field[0], field[1], field[2], field[3], field[4],
             field[5]);
    return buffer;
}

static std::string getProtocol(const uint16_t protocol)
{
    constexpr auto bufferSize = 16;
    char buffer[bufferSize];
    snprintf(buffer, bufferSize, "0x%.4X", ntohs(protocol));
    return buffer;
}

const uint8_t* deserializeEthernetHeaderToJson(const uint8_t* packetBegin, const uint8_t* packetEnd, Json& outputJson)
{
    constexpr int headerSize = sizeof(ethhdr);

    auto packetSize = packetEnd - packetBegin;
    if (headerSize > packetSize)
        THROW(std::runtime_error, "Could not extract ethernet header from packet -- the packet must have at least ",
              headerSize, " bytes and not ", packetSize, " bytes");

    auto header = reinterpret_cast<const ethhdr*>(packetBegin);
    auto& map = outputJson.get<std::map<std::string, Json>>();
    map.emplace("destinationMacAddress", getMacAddress(header->h_dest));
    map.emplace("sourceMacAddress", getMacAddress(header->h_source));
    map.emplace("macProtocol", getProtocol(header->h_proto));
    map.emplace("packetSize", static_cast<int>(packetSize));
    return packetBegin + headerSize;
}

}
