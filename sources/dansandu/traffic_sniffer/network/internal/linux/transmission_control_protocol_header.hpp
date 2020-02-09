#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <linux/tcp.h>
#include <sstream>
#include <string>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::transmission_control_protocol_header
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

Json deserializeTransmissionControlProtocolHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd)
{
    constexpr int headerSize = sizeof(tcphdr);
    auto layerSize = packetEnd - layerBegin;
    if (headerSize > layerSize)
        THROW(std::invalid_argument,
              "Could not extract transmission control protocol header from packet -- the header must have at least ",
              headerSize, " bytes instead of ", layerSize, " bytes");

    auto payloadSize = packetEnd - (layerBegin + headerSize);
    auto header = reinterpret_cast<const tcphdr*>(layerBegin);
    auto json = std::map<std::string, Json>();
    json.emplace("tcpFlags", Json::from<std::string>(getTcpFlags(header)));
    json.emplace("destinationPort", Json::from<int>(ntohs(header->dest)));
    json.emplace("sourcePort", Json::from<int>(ntohs(header->source)));
    json.emplace("tcpHeaderLength", Json::from<int>(headerSize));
    json.emplace("payloadSize", Json::from<int>(payloadSize));
    return Json::from<std::map<std::string, Json>>(std::move(json));
}

}
