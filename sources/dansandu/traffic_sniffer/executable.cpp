#include "dansandu/ballotin/time.hpp"
#include "dansandu/traffic_sniffer/asynchronous_packet_deserializer.hpp"
#include "dansandu/traffic_sniffer/network/raw_socket.hpp"

using dansandu::ballotin::time::getDatetimeAsString;
using dansandu::traffic_sniffer::asynchronous_packet_deserializer::AsynchronousPacketDeserializer;
using dansandu::traffic_sniffer::network::raw_socket::RawSocket;

int main(int argc, char** argv)
{
    auto timestampFormat = "%H:%M:%S%z %d-%m-%Y";
    auto logFileName = (argc >= 2) ? argv[1] : "log.txt";
    auto packetDeserializer = AsynchronousPacketDeserializer{logFileName};
    auto rawSocket = RawSocket{};
    while (true)
    {
        auto packet = rawSocket.waitForPacket();
        packetDeserializer.deserialize(std::move(packet), getDatetimeAsString(timestampFormat));
    }
    return 0;
}
