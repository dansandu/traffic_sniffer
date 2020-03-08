#include "dansandu/traffic_sniffer/asynchronous_packet_deserializer.hpp"
#include "dansandu/ballotin/exception.hpp"
#include "dansandu/jelly/json.hpp"
#include "dansandu/traffic_sniffer/concurrency/queued_task_executor.hpp"
#include "dansandu/traffic_sniffer/network/packet.hpp"

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using dansandu::jelly::json::Json;
using dansandu::traffic_sniffer::concurrency::queued_task_executor::QueuedTaskExecutor;
using dansandu::traffic_sniffer::network::packet::deserializePacketHeadersToJson;

namespace dansandu::traffic_sniffer::asynchronous_packet_deserializer
{

AsynchronousPacketDeserializer::AsynchronousPacketDeserializer(const std::string& outputFilePath)
    : outputFile_{outputFilePath}
{
    if (!outputFile_)
        THROW(std::invalid_argument, "Could not open file '", outputFilePath, "' for packet deserialization");
}

void AsynchronousPacketDeserializer::deserialize(std::vector<uint8_t> packet, std::string timestamp)
{
    queuedTaskExecutor_.addTask([this, packet = std::move(packet), timestamp = std::move(timestamp)]() {
        auto json = Json{std::map<std::string, Json>{{"timestamp", std::move(timestamp)}}};
        deserializePacketHeadersToJson(packet, json);
        outputFile_ << json << std::endl;
    });
}

AsynchronousPacketDeserializer::~AsynchronousPacketDeserializer()
{
    outputFile_.close();
}

}
