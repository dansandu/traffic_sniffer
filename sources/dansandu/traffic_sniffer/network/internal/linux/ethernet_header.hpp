#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/if_ether.h>
#include <map>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::ethernet_header
{

static auto getMacAddress(const uint8_t* field)
{
    constexpr auto bufferSize = 25;
    char buffer[bufferSize];
    snprintf(buffer, bufferSize, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", field[0], field[1], field[2], field[3], field[4],
             field[5]);
    return std::string{buffer};
}

static auto getProtocol(const uint16_t field)
{
    constexpr auto bufferSize = 8;
    char buffer[bufferSize];
    snprintf(buffer, bufferSize, "0x%.4X", ntohs(field));
    return std::string{buffer};
}

Json deserializeEthernetHeaderToJson(const uint8_t* packetBegin, const uint8_t* packetEnd)
{
    constexpr int ethernetHeaderSize = sizeof(ethhdr);

    auto packetSize = packetEnd - packetBegin;
    if (ethernetHeaderSize > packetSize)
        THROW(std::runtime_error, "Could not extract ethernet header from packet -- the packet must have at least ",
              ethernetHeaderSize, " bytes and not ", packetSize, " bytes");

    auto ethernetHeader = reinterpret_cast<const ethhdr*>(packetBegin);
    auto json = std::map<std::string, Json>();
    json.emplace("destinationMacAddress", Json::from<std::string>(getMacAddress(ethernetHeader->h_dest)));
    json.emplace("sourceMacAddress", Json::from<std::string>(getMacAddress(ethernetHeader->h_source)));
    json.emplace("macProtocol", Json::from<std::string>(getProtocol(ethernetHeader->h_proto)));
    json.emplace("packetSize", Json::from<int>(packetSize));
    return Json::from<std::map<std::string, Json>>(std::move(json));
}

}
