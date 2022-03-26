#ifndef LIB_OPEN_VPN_SIMPLE_PACKET_CRAFTER_H
#define LIB_OPEN_VPN_SIMPLE_PACKET_CRAFTER_H
#include <memory>
#include <string>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/ip/ipcommon.hpp>
#include "tins/tins.h"

//Header + payload maximum size for maximum packet IPV4 or IPV6
const int IP_PACKET_MAX_SIZE = 65535 + 40;
class SimplePacketCrafter
{
public:
    void setSourceIPV4(std::string address)
    {
        ipv4address = address;
    }
    void setSourceIPV6(std::string address)
    {
        ipv6address = address;
    }

    //TODO: should I parse the packet here to see if it's really an IP packet?
    //TODO: multiple optimizations here (no libtins and use stack of size max of ip packet size)
    static bool replaceSourceAddress(uint8_t *packet, size_t size, std::string sourceAddress)
    {
        if (size==0) {
            throw std::runtime_error("replaceSourceAddress exception: empty packet");
        }
        Tins::IP tins_packet = Tins::IP(packet, size);
        tins_packet.src_addr(sourceAddress);
        auto serialized_tins_packet = tins_packet.serialize();
        size_t tins_packet_size = serialized_tins_packet.size();
        if (size!=tins_packet_size) {
            throw std::runtime_error("size of tins packet and original packet differ");
        }
        for (size_t i = 0; i < size; i++)
        {
            packet[i] = serialized_tins_packet[i];
        }
        return true;
    }

    static bool replaceDestinationAddress(uint8_t *packet, size_t size, std::string destinationAddressIpv4, std::string destinationAddressIpv6)
    {
        if (size==0) {
            throw std::runtime_error("replaceSourceAddress exception: empty packet");
        }
        Tins::IP tins_packet = Tins::IP(packet, size);
        if (tins_packet.version()==4) {
            if (destinationAddressIpv4.empty()) {
                throw std::runtime_error("replaceDestinationAddress exception: tried to fill ipv6 packet but destinationAddressIpv6 is empty");
            }
            tins_packet.dst_addr(destinationAddressIpv4);
        } else if (tins_packet.version()==6) {
            if (destinationAddressIpv6.empty()) {
                throw std::runtime_error("replaceDestinationAddress exception: tried to fill ipv6 packet but destinationAddressIpv6 is empty");
            }
            tins_packet.dst_addr(destinationAddressIpv6);
        }
        
        auto serialized_tins_packet = tins_packet.serialize();
        size_t tins_packet_size = serialized_tins_packet.size();
        if (size!=tins_packet_size) {
            throw std::runtime_error("size of tins packet and original packet differ");
        }
        for (size_t i = 0; i < size; i++)
        {
            packet[i] = serialized_tins_packet[i];
        }
        return true;
    }

    void fillIPSource(openvpn::BufferAllocated &buf)
    {
        if (buf.size()<1) {
            throw std::runtime_error("fillIPSource exception: buffer empty");
        }
        int ipVersion = openvpn::IPCommon::version(buf[0]);

        if (ipv4address.size() > IP_PACKET_MAX_SIZE || ipv6address.size() > IP_PACKET_MAX_SIZE)
        {
            throw std::runtime_error("ipv4/6address size too big");
        }
        if (ipVersion == 4)
        {
            const unsigned int ipv4HeaderSize = 32;
            if (!ipv4address.empty() && buf.size() > ipv4HeaderSize)
            {
                replaceSourceAddress(buf.data(), buf.size(), ipv4address);
            }
            else
            {
                throw std::runtime_error("ipv4address empty or buf with small size");
            }
        }
        else if (ipVersion == 6)
        {
            const unsigned int ipv6HeaderSize = 288;
            if (!ipv6address.empty() && buf.size() > ipv6HeaderSize)
            {
                replaceSourceAddress(buf.data(), buf.size(), ipv4address);
            }
            else
            {
                throw std::runtime_error("ipv6address empty or buf with small size");
            }
        }
        else
        {
            throw std::runtime_error("couldn't detect ip version of buffer");
        }
    }

private:
    std::string ipv4address;
    std::string ipv6address;
};

#endif //LIB_OPEN_VPN_SIMPLE_PACKET_CRAFTER_H