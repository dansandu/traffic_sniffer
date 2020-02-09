#pragma once

#include "dansandu/ballotin/exception.hpp"
#include "dansandu/traffic_sniffer/network/raw_socket.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace dansandu::traffic_sniffer::network::raw_socket
{

struct Implementation
{
    Implementation(int socketDescriptor) : socketDescriptor{socketDescriptor}
    {
    }

    int socketDescriptor;
};

static void free(void* p) noexcept
{
    auto implementation = static_cast<Implementation*>(p);
    close(implementation->socketDescriptor);
    delete implementation;
}

RawSocket::RawSocket() : implementation_{nullptr, &free}
{
    if (auto socketDescriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); socketDescriptor != -1)
    {
        implementation_.reset(new Implementation{socketDescriptor});
    }
    else
    {
        THROW(std::runtime_error, "Could not create raw socket -- ", std::strerror(errno));
    }
}

RawSocket::RawSocket(RawSocket&& other) noexcept : implementation_{std::move(other.implementation_)}
{
}

RawSocket& RawSocket::operator=(RawSocket&& other) noexcept
{
    implementation_ = std::move(other.implementation_);
    return *this;
}

RawSocket::~RawSocket() noexcept
{
}

std::vector<uint8_t> RawSocket::waitForPacket() const
{
    constexpr auto maximumPacketSize = 65536;

    auto packet = std::vector<uint8_t>(maximumPacketSize, 0);
    auto address = sockaddr_storage{};
    auto addressSize = socklen_t{sizeof(address)};
    auto receiveFlags = 0;
    auto socketDescriptor = static_cast<Implementation*>(implementation_.get())->socketDescriptor;

    if (auto packetSize = recvfrom(socketDescriptor, &packet.front(), maximumPacketSize, receiveFlags,
                                   reinterpret_cast<sockaddr*>(&address), &addressSize);
        packetSize != -1)
    {
        packet.erase(packet.begin() + packetSize, packet.end());
        return packet;
    }
    THROW(std::runtime_error, "Could not read packet from raw socket -- ", std::strerror(errno));
}

}
