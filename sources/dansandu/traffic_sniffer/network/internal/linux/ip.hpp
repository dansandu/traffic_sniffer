#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <linux/ip.h>

using dansandu::jelly::json::Json;

namespace dansandu::traffic_sniffer::network::ip
{

static auto getIpProtocol(int id)
{
    switch (id)
    {
    case IPPROTO_IP:
        return "IP";
    case IPPROTO_ICMP:
        return "ICMP";
    case IPPROTO_IGMP:
        return "IGMP";
    case IPPROTO_IPIP:
        return "IPIP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_EGP:
        return "EGP";
    case IPPROTO_PUP:
        return "PUP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_IDP:
        return "IDP";
    case IPPROTO_TP:
        return "TP";
    case IPPROTO_DCCP:
        return "DCCP";
    case IPPROTO_IPV6:
        return "IPV6";
    case IPPROTO_RSVP:
        return "RSVP";
    case IPPROTO_GRE:
        return "GRE";
    case IPPROTO_ESP:
        return "ESP";
    case IPPROTO_AH:
        return "AH";
    case IPPROTO_MTP:
        return "MTP";
    case IPPROTO_BEETPH:
        return "BEETPH";
    case IPPROTO_ENCAP:
        return "ENCAP";
    case IPPROTO_PIM:
        return "PIM";
    case IPPROTO_COMP:
        return "COMP";
    case IPPROTO_SCTP:
        return "SCTP";
    case IPPROTO_UDPLITE:
        return "UDPLITE";
    case IPPROTO_MPLS:
        return "MPLS";
    case IPPROTO_RAW:
        return "RAW";
    default:
        THROW(std::runtime_error, "Could not stringfy ip protocol -- unrecognized ip protocol");
    }
}

const uint8_t* deserializeIpHeaderToJson(const uint8_t* layerBegin, const uint8_t* packetEnd, Json& outputJson)
{
    int headerSize = sizeof(iphdr);
    auto layerSize = packetEnd - layerBegin;
    if (headerSize > layerSize)
        THROW(std::invalid_argument,
              "Could not extract internet protocol header from packet -- the header must have at least ", headerSize,
              " bytes instead of ", layerSize, " bytes");

    auto header = reinterpret_cast<const iphdr*>(layerBegin);
    headerSize = header->ihl * 4; // ihl : header length in DWORDS, multiplying by 4 yields bytes

    sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = header->saddr;

    sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = header->daddr;

    auto& map = outputJson.get<std::map<std::string, Json>>();
    map.emplace("ipVersion", Json::from<int>(header->version));
    map.emplace("ipHeaderLength", Json::from<int>(headerSize));
    map.emplace("sourceIp", Json::from<std::string>(inet_ntoa(source.sin_addr)));
    map.emplace("destinationIp", Json::from<std::string>(inet_ntoa(destination.sin_addr)));
    map.emplace("ipProtocol", Json::from<std::string>(getIpProtocol(header->protocol)));
    return layerBegin + headerSize;
}

}
