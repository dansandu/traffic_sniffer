#pragma once

#include "dansandu/ballotin/type_traits.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace dansandu::traffic_sniffer::network::raw_socket
{

class RawSocket : private dansandu::ballotin::type_traits::Uncopyable
{
public:
    RawSocket();

    RawSocket(RawSocket&& other) noexcept;

    ~RawSocket() noexcept;

    RawSocket& operator=(RawSocket&& other) noexcept;

    std::vector<uint8_t> waitForPacket() const;

private:
    std::unique_ptr<void, void (*)(void*)> implementation_;
};

}
