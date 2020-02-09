#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/ip.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::ip::deserializeIpHeaderToJson;

TEST_CASE("Ip")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {
            0x45,                   // version and header length
            0x00,                   // priority and type of service
            0x00, 0x50,             // total length
            0x41, 0x16,             // identification
            0x02, 0x00,             // fragment flags and offset
            0x80,                   // time to live
            0x06,                   // protocol
            0x00, 0x00,             // header checksum
            0xC0, 0xA8, 0x0A, 0x2D, // source ip address
            0x51, 0xC0, 0x69, 0x01  // destination ip address
        };                          // no options

        auto json = Json::from<std::map<std::string, Json>>();
        deserializeIpHeaderToJson(std::begin(packet), std::end(packet), json);
        const auto& map = json.get<std::map<std::string, Json>>();

        REQUIRE(map.at("ipVersion").get<int>() == 4);
        REQUIRE(map.at("ipHeaderLength").get<int>() == 20);
        REQUIRE(map.at("sourceIp").get<std::string>() == "192.168.10.45");
        REQUIRE(map.at("destinationIp").get<std::string>() == "81.192.105.1");
        REQUIRE(map.at("ipProtocol").get<std::string>() == "TCP");
    }
}
