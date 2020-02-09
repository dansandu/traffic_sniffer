#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/tcp.h>
#include <sstream>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::tcp
{

static auto getTcpFlags(const tcphdr* header)
{
    auto flags = std::ostringstream{};
    if (header->cwr)
        flags << "CWR ";
    if (header->ece)
        flags << "ECE ";
    if (header->urg)
        flags << "URG ";
    if (header->ack)
        flags << "ACK ";
    if (header->psh)
        flags << "PSH ";
    if (header->rst)
        flags << "RST ";
    if (header->syn)
        flags << "SYN ";
    if (header->fin)
        flags << "FIN ";
    return flags.str();
}

const uint8_t* deserializeTcpHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd, Json& outputJson)
{
    constexpr int headerSize = sizeof(tcphdr);
    auto layerSize = packetEnd - layerBegin;
    if (headerSize > layerSize)
        THROW(std::invalid_argument,
              "Could not extract transmission control protocol header from packet -- the header must have at least ",
              headerSize, " bytes instead of ", layerSize, " bytes");

    auto header = reinterpret_cast<const tcphdr*>(layerBegin);
    auto tcpDataOffset = header->doff * 4;
    auto& map = outputJson.get<std::map<std::string, Json>>();
    map.emplace("tcpFlags", Json::from<std::string>(getTcpFlags(header)));
    map.emplace("sourcePort", Json::from<int>(ntohs(header->source)));
    map.emplace("destinationPort", Json::from<int>(ntohs(header->dest)));
    map.emplace("tcpDataOffset", Json::from<int>(tcpDataOffset));
    return layerBegin + tcpDataOffset;
}

}
