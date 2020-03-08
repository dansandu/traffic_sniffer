#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/tcp.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::tcp::deserializeTcpHeaderToJson;

TEST_CASE("Tcp")
{
    SECTION("json deserialization")
    {
        uint8_t packet[] = {
            0x0E, 0x09,             // source port
            0x0B, 0x96,             // destination port
            0x00, 0x00, 0x00, 0x00, // sequence number
            0x00, 0x00, 0x00, 0x00, // acknowledgment number
            0x50, 0x6B,             // data offset and flags
            0x00, 0x00,             // window size
            0x00, 0x00,             // checksum
            0x00, 0x00,             // urgent pointer
            0x01, 0x02, 0x03, 0x04, // payload
            0x05, 0x06, 0x07, 0x08  // payload
        };
        auto json = Json{std::map<std::string, Json>{}};
        deserializeTcpHeaderToJson(std::begin(packet), std::end(packet), json);

        REQUIRE(json["tcpFlags"].get<std::string>() == "ECE URG PSH SYN FIN ");
        REQUIRE(json["sourcePort"].get<int>() == 3593);
        REQUIRE(json["destinationPort"].get<int>() == 2966);
        REQUIRE(json["tcpDataOffset"].get<int>() == 20);
    }
}
