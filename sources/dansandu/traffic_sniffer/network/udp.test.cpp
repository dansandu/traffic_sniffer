#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/udp.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::udp::deserializeUdpHeaderToJson;

TEST_CASE("Udp")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {
            0x01, 0x0E, // source port
            0x0F, 0x33, // destination port
            0x00, 0x08, // length
            0x00, 0x00  // checksum
        };
        auto json = Json{std::map<std::string, Json>{}};
        deserializeUdpHeaderToJson(std::begin(packet), std::end(packet), json);

        REQUIRE(json["sourcePort"].get<int>() == 270);
        REQUIRE(json["destinationPort"].get<int>() == 3891);
        REQUIRE(json["udpLength"].get<int>() == 8);
    }
}
