#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/user_datagram_protocol_header.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::user_datagram_protocol_header::deserializeUserDatagramProtocolHeaderToJson;

TEST_CASE("User datagram protocol header")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {
            0x01, 0x0E, // source port
            0x0F, 0x33, // destination port
            0x00, 0x00, // length
            0x00, 0x00  // checksum
        };

        auto json = deserializeUserDatagramProtocolHeaderToJson(std::begin(packet), std::end(packet));
        const auto& map = json.get<std::map<std::string, Json>>();

        REQUIRE(map.at("sourcePort").get<int>() == 270);
        REQUIRE(map.at("destinationPort").get<int>() == 3891);
        REQUIRE(map.at("packetLength").get<int>() == 8);
    }
}
