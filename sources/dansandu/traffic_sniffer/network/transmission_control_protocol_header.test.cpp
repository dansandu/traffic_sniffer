#include "catchorg/catch/catch.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/network/transmission_control_protocol_header.hpp"

#include <cstdint>
#include <map>
#include <string>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::network::transmission_control_protocol_header::
    deserializeTransmissionControlProtocolHeaderToJson;

TEST_CASE("Transmission control protocol header")
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

        auto json = deserializeTransmissionControlProtocolHeaderToJson(std::begin(packet), std::end(packet));
        const auto& map = json.get<std::map<std::string, Json>>();

        REQUIRE(map.at("tcpFlags").get<std::string>() == "ECE URG PSH SYN FIN ");
        REQUIRE(map.at("sourcePort").get<int>() == 3593);
        REQUIRE(map.at("destinationPort").get<int>() == 2966);
        REQUIRE(map.at("tcpHeaderLength").get<int>() == 20);
        REQUIRE(map.at("payloadSize").get<int>() == 8);
    }
}
