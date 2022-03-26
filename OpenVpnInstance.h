#ifndef LIB_OPENVPN_SOCKET_INSTANCE_H
#define LIB_OPENVPN_SOCKET_INSTANCE_H
//#include "LibOpenVPN.h"
#include "OpenVpnClient.hpp"
#include "OpenVpnUtils.h"
#include "tins/ip.h"
#include "SimplePacketCrafter.h"
#include "VirtualVPNAsioStream.h"
#include <atomic>
#include <chrono>
#include <thread>
#include <iostream>
#include <stdint.h>
#include <memory>

struct Callbacks
{
    void *user_data;
    int (*on_read_allocate)(uint8_t **buffer, size_t *size, void *user_data);
    int (*on_write)(const uint8_t *buffer, size_t size, void *user_data);
    int (*on_log)(const uint8_t *buffer, void *user_data);
    int (*on_event)(const uint8_t *name, const uint8_t *info, bool error, bool fatal, void *user_data);
    void (*destroy)(void *user_data);
};

void callbacksLog(std::string s, Callbacks& callbacks) {
    callbacks.on_log(reinterpret_cast<const uint8_t*>(s.c_str()), callbacks.user_data);
} 

/*
void callbacksLog(const char* s, Callbacks& callbacks) {
    callbacks.on_log(reinterpret_cast<const uint8_t*>(s), callbacks.user_data);
} 

void callbacksLog(const uint8_t* s, Callbacks& callbacks) {
    callbacks.on_log(s, len, callbacks.user_data);
} 
*/

void callbacksOnEvent(const Event& event, Callbacks& callbacks) {
    callbacks.on_event(reinterpret_cast<const uint8_t*>(event.name.c_str()), reinterpret_cast<const uint8_t*>(event.info.c_str()), event.error, event.fatal, callbacks.user_data);
} 
class OpenVPNSocket
{
public:
    OpenVPNSocket(std::string profile, std::string username, std::string password, Callbacks callbacks, std::string replacementIpv4, std::string replacementIpv6)
    {
        this->vAsioStream = std::make_shared<VAsioStream>();
        //TODO: deinit process on destruct?
        //TODO: init only once or can I init lots of times?
        OpenVPNClient::init_process();
        this->callbacks = callbacks;
        this->openVpnClient = build_openvpn_client_from_profile_string(profile, username, password, this->vAsioStream, replacementIpv4, replacementIpv6);
        this->openVpnClient->setLogFunction([this](std::string message){
            callbacksLog(message, this->callbacks);
        });
        this->openVpnClient->setOnEvent([this](const Event& event){
            callbacksOnEvent(event, this->callbacks);
        });
    }

    ~OpenVPNSocket()
    {
        _shouldContinue.store(false);
        if (this->thread.joinable())
            this->thread.join();
    }

    void run()
    {
        _shouldContinue.store(true);
        this->thread = std::thread(&OpenVPNSocket::asioLoop, this);
        callbacksLog("finished running libopenvpn thread", this->callbacks);
        //ALOGV("did finish run thread libopenvpn");
    }

    uint8_t connect()
    {
        //auto openVpnClient_ = &this->openVpnClient
        connectThread = std::thread([this]() { this->openVpnClient->connect(); });
        return 0;
    }

    uint8_t disconnect()
    {
        //TODO!!!!!! How to disconnect??
        callbacksLog("WARNING: disconnect not implemented yet", this->callbacks);
        return 1;
    }

    uint8_t send(uint8_t *data, size_t size)
    {
        auto b = libopenvpn::Buffer<uint8_t>::copyFromBuffer(data, size);
        this->vAsioStream->queue_write_some(b);
        return 0;
    }

    //written_size tells how many bytes were written. returned value is error value
    uint8_t receive(uint8_t *buffer, size_t buffer_size, size_t *written_size)
    {
        throw std::invalid_argument("receive deprecated");
    }

    /*
        `buffer`: destination to write the read_just result
        `buffer_size`: size of `buffer`
        `written_size`: we write to it the amount received from read_just so the caller knows how much of `buffer` we filled
    */
    uint8_t receive_just(uint8_t *buffer, size_t buffer_size, size_t *written_size)
    {
        //Just write data here so it does not point to invalid data, but `written_size` shouldn't be checked if return is not 0
        *written_size = 0;
        size_t n = 0;
        //Reads up to buffer_size bytes from vAsioStream and copies them to `buffer`
        auto b = this->vAsioStream->read_just(buffer_size, [&n, buffer, buffer_size](const uint8_t* begin, const uint8_t* end){
            n = end-begin;
            if (n > buffer_size) {
                //Currently does not throw because we return error in this case below. Anyways, we shouldn't ever arrive at this situation
                //throw std::runtime_error("end-begin > buffer_size");
            } else {
                //Safe to copy
                std::copy(begin, end, buffer);
            }
        });
        //If there was data to read
        if (b)
        {
            if (n > buffer_size) {
                //We shouldn't arrive here
                return 1;
            } else {
                //Tells the caller of this function how much we wrote 
                *written_size = n;
                return 0;
            }
        }
        else
        {
            //There was no data to read (no buffer on vAsioStream right now)
            return 2;
        }
    }

    //Deprecated
    void asioLoop()
    {
        throw std::runtime_error("asioLoop deprecated");
        /*
        while (shouldContinue())
        {
            //vpn_client_virtual_tun_receive_instantly
            //auto buffer_ = l.virtualTunReceiveInstantly();
            uint8_t *buffer;
            size_t size;
            int r = this->callbacks.on_read_allocate(&buffer, &size, this->callbacks.user_data);
            if (r != 0)
            {
                throw std::invalid_argument("error on on_read_allocate");
            }
            if (r > 0)
            {
                //auto buffer = buffer_.value();
                //TODO: don't need to copy here, as `CBuffer` already owns this data?
                //uint8_t *raw_buffer = buffer->data.get();
                //std::cout << "gonna send to openvpn: " << std::endl;
                //printBuffer(b->data(), b->size());
                //std::cout << "----------------received from openvpn!!!!" << std::endl;
                //printBuffer(raw_buffer, buffer.len);
                auto b = libopenvpn::Buffer<uint8_t>::copyFromBuffer(buffer, size);
                //SimplePacketCrafter::replaceDestinationAddress(b->data(), b->size(), "192.168.69.1");
                this->vAsioStream->queue_write_some(b);
                //std::cout << "o" << std::flush;
            }
            //TODO: make this delete automatic
            delete[] buffer;

            auto b = this->vAsioStream->read_all();
            if (b)
            {
                //replace packet with IP right destination for this stack
                //TODO!!!!: put dynamic IP, take off this hardcoded one
                //SimplePacketCrafter::replaceDestinationAddress(b->data(), b->size(), "192.168.69.1");
                this->callbacks.on_write(b->data(), b->size(), this->callbacks.user_data);
                //l.virtualTunSend(b->data(), b->size());
                //std::cout << "y" << std::flush;
            }

            //TODO: do not wait, use condition variables
            //Wait in milliseconds
            //Stack::phy_wait(2);
            //std::this_thread::sleep_for(std::chrono::milliseconds(0.5));
            std::this_thread::sleep_for(std::chrono::microseconds(500));
            //---l.phy_wait(10);
        }
        */
    }

    bool shouldContinue()
    {
        return this->_shouldContinue.load();
    }

public:
    Callbacks callbacks;
private:
    std::shared_ptr<VAsioStream> vAsioStream;
    std::unique_ptr<OpenVPNClient> openVpnClient;
    std::thread thread;
    std::thread connectThread;
    //todo: default value to false
    std::atomic<bool> _shouldContinue;
};

extern "C"
{
    OpenVPNSocket *openvpn_client_new(const char *profile,const char *username,const char *password, Callbacks callbacks, const char* replacementIpv4, const char* replacementIpv6)
    {
        std::string profileString(profile);
        return new OpenVPNSocket(profileString, username, password, callbacks, replacementIpv4, replacementIpv6);
    }

    uint8_t openvpn_client_run(OpenVPNSocket *client)
    {
        throw new std::runtime_error("openvpn_client_run deprecated");
        try
        {
            // do stuff, calling client.callbacks.on_read and friends when
            // things happen.

            return 0;
        }
        catch (std::exception &e)
        {
            return -1;
        }
    }

    uint8_t openvpn_client_connect(OpenVPNSocket *client)
    {
        return client->connect();
    }

    uint8_t openvpn_client_disconnect(OpenVPNSocket *client)
    {
        return client->disconnect();
    }

    uint8_t openvpn_client_send(uint8_t *buffer, size_t size, OpenVPNSocket *client)
    {
        return client->send(buffer, size);
    }

    uint8_t openvpn_client_receive(uint8_t *buffer, size_t buffer_size, size_t *written_size, OpenVPNSocket *client)
    {
        return client->receive(buffer, buffer_size, written_size);
    }

    uint8_t openvpn_client_receive_just(uint8_t *buffer, size_t buffer_size, size_t *written_size, OpenVPNSocket *client)
    {
        return client->receive_just(buffer, buffer_size, written_size);
    }

    void openvpn_client_free(OpenVPNSocket *client)
    {
        delete client;
    }

    uint8_t *openvpn_client_allocate(size_t size)
    {
        return new uint8_t[size]();
    }

    void openvpn_client_deallocate(uint8_t* buffer)
    {
        delete[] buffer;
    }
}

#endif //LIB_OPENVPN_SOCKET_INSTANCE_H