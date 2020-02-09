#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/ethernet_header.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::ethernet_header::deserializeEthernetHeaderToJson;

TEST_CASE("Ethernet header")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {0x02, 0x04, 0x08, 0xFA, 0xAF, 0xAC, 0x07, 0xCC, 0x55, 0x66, 0x8f, 0xFF, 0x01, 0x10};

        auto json = deserializeEthernetHeaderToJson(std::begin(packet), std::end(packet));

        const auto& map = json.get<std::map<std::string, Json>>();

        REQUIRE(map.at("destinationMacAddress").get<std::string>() == "02:04:08:FA:AF:AC");
        REQUIRE(map.at("sourceMacAddress").get<std::string>() == "07:CC:55:66:8F:FF");
        REQUIRE(map.at("macProtocol").get<std::string>() == "0x0110");
    }
}
