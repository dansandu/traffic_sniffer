#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/ethernet.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::ethernet::deserializeEthernetHeaderToJson;

TEST_CASE("Ethernet header")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {0x02, 0x04, 0x08, 0xFA, 0xAF, 0xAC, 0x07, 0xCC, 0x55, 0x66, 0x8f, 0xFF, 0x08, 0x00};
        auto packetSize = sizeof(packet) / sizeof(*packet);
        auto json = Json{std::map<std::string, Json>{}};
        deserializeEthernetHeaderToJson(std::begin(packet), std::end(packet), json);

        REQUIRE(json["destinationMacAddress"].get<std::string>() == "02:04:08:FA:AF:AC");
        REQUIRE(json["sourceMacAddress"].get<std::string>() == "07:CC:55:66:8F:FF");
        REQUIRE(json["macProtocol"].get<std::string>() == "0x0800");
        REQUIRE(json["packetSize"].get<int>() == packetSize);
    }
}
