#pragma once

#include "dansandu/ballotin/type_traits.hpp"
#include "dansandu/traffic_sniffer/concurrency/queued_task_executor.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace dansandu::traffic_sniffer::asynchronous_packet_deserializer
{

class AsynchronousPacketDeserializer : private dansandu::ballotin::type_traits::Uncopyable,
                                       private dansandu::ballotin::type_traits::Immovable
{
public:
    explicit AsynchronousPacketDeserializer(const std::string& outputFilePath);

    void deserialize(std::vector<uint8_t> packet, std::string timestamp);

    ~AsynchronousPacketDeserializer();

private:
    dansandu::traffic_sniffer::concurrency::queued_task_executor::QueuedTaskExecutor queuedTaskExecutor_;
    std::ofstream outputFile_;
};

}
