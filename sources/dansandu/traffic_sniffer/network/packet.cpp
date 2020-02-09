#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/ethernet.hpp"
#include "dansandu/traffic_sniffer/network/ip.hpp"
#include "dansandu/traffic_sniffer/network/tcp.hpp"
#include "dansandu/traffic_sniffer/network/udp.hpp"

#include <cstdint>
#include <map>
#include <vector>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::ethernet::deserializeEthernetHeaderToJson;
using dansandu::traffic_sniffer::network::ip::deserializeIpHeaderToJson;
using dansandu::traffic_sniffer::network::tcp::deserializeTcpHeaderToJson;
using dansandu::traffic_sniffer::network::udp::deserializeUdpHeaderToJson;

namespace dansandu::traffic_sniffer::network::packet
{

const uint8_t* deserializePacketHeadersToJson(const std::vector<uint8_t>& packet, Json& outputJson)
{
    auto begin = &packet.front();
    auto end = begin + packet.size();
    auto secondLayer = deserializeEthernetHeaderToJson(begin, end, outputJson);
    const auto& macProtocol = outputJson.get<std::map<std::string, Json>>().at("macProtocol").get<std::string>();
    if (macProtocol == "0x0800")
    {
        auto thirdLayer = deserializeIpHeaderToJson(secondLayer, end, outputJson);
        auto ipProtocol = outputJson.get<std::map<std::string, Json>>().at("ipProtocol").get<std::string>();
        if (ipProtocol == "TCP")
        {
            return deserializeTcpHeaderToJson(thirdLayer, end, outputJson);
        }
        else if (ipProtocol == "IP")
        {
            return deserializeUdpHeaderToJson(thirdLayer, end, outputJson);
        }
    }
    return secondLayer;
}

}
