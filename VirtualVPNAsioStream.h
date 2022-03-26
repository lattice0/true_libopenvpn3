
#ifndef OPENVPN_TUN_ASIO_STYLE_DEQUE_H
#define OPENVPN_TUN_ASIO_STYLE_DEQUE_H
#include <iostream>
#include <thread>
#include "openvpn/io/io.hpp"
#include <atomic>
#include <condition_variable>
#include <queue>
#include <optional>
#include "AsioAsyncChannel.h"
#include "AsyncChannel.h"

namespace libopenvpn
{
    template <class ReadHandler, class T>
    class AsioReadCall : public AsioReader<T>
    {
    public:
        AsioReadCall(const openvpn_io::mutable_buffer &buffer,
                     ReadHandler &&handler) : buffer(buffer), handler(std::move(handler))
        {
        }

        ~AsioReadCall()
        {
            //ALOGV("~AsioReadCall ");
        }

        size_t size()
        {
            return this->buffer.size();
        }

        void receive(const T* _buffer, size_t amountToReceive)
        {
            if (amountToReceive>this->buffer.size()) {
                 throw std::runtime_error("AsioReadCall buffer too small for 'receive' operation\n");
            }
            std::copy(_buffer, _buffer + amountToReceive, static_cast<T*>(this->buffer.data()));
            this->amountReceived = amountToReceive;
        }

        void deliver()
        {
            handler(openvpn_io::error_code(), amountReceived);
        }

    private:
        openvpn_io::mutable_buffer buffer;
        size_t amountReceived;
        ReadHandler handler;
    };

    /*
        Subsitutes stream_descriptor from ASIO in OpenVPN3 (https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/reference/posix__stream_descriptor.html)
        This class is specific for libopenvpn, because it crafts IP packets with the given payload 
        before sending them. 
    */
    template <class T>
    class VirtualVPNAsioStream
    {
    public:
        VirtualVPNAsioStream()
        {
        }

        ~VirtualVPNAsioStream()
        {
            //ALOGV("~VirtualVPNAsioStream\n");
        }

        //called by OpenVPN3 to queue asynchronous reads with data from my app
        template <class ReadHandler>
        //To be used by the OpenVPN endpoint
        void async_read_some(
            const openvpn_io::mutable_buffer &buffer,
            ReadHandler &&handler)
        {
            //std::cout << "VirtualVPNAsioStream async_read_some called " << std::endl;
            channelA.emplace_reader(std::make_shared<AsioReadCall<ReadHandler, T>>(buffer, std::move(handler)));
        }

        //To be used by the OpenVPN endpoint
        std::size_t write_some(const openvpn_io::const_buffer &buffer)
        {
            auto b = Buffer<uint8_t>::copyFromBuffer(static_cast<const uint8_t*>(buffer.data()), buffer.size());
            channelB.emplace_buffer(b);
            //On ASIO it should return the ammount written if something
            //happened and it couldn't write everything. Here,
            //we always return the entire buffer size since we wrote everything
            return buffer.size();
        }
        /*
        //A way for the app to provide a callback so OpenVPN3 can write to it
        void queue_read_some(std::function<something...> callback)
        {

        }
        */
        /*
        To be used by the other endpoint (gives a chance for it to
        queue a write so we don't need to copy)
        */
        void queue_write_some(Buffer<T> buffer)
        {
            channelA.emplace_buffer(buffer);
        }

        //To be used by the other endpoint
        template <class ReadHandler>
        void async_read_some(
            Buffer<T> buffer,
            ReadHandler &&handler)
        {
            channelB.emplace_reader(std::make_shared<AsioReadCall<ReadHandler, T>>(buffer, std::move(handler)));
        }

        std::optional<Buffer<T>> read_all()
        {
            throw std::invalid_argument("read_all deprecated");
            return std::nullopt;
            //return channelB.read_all();
        }

        bool read_just(size_t just, std::function<void(uint8_t*, uint8_t*)> onConsume)
        {
            return channelB.read_just(just, onConsume);
        }

        void cancel()
        {
        }

        void release()
        {
        }

        void close()
        {
        }

    private:
        //TODO: change these by shared_ptr versions and take shared_ptr out of AsyncChannel class to make it clearer?
        AsyncChannel<AsioReader<T>, Buffer<T>> channelA{true};
        //We're not going to use the match functionality on channelB
        //since we're reading directly with read_all
        AsyncChannel<AsioReader<T>, Buffer<T>> channelB{false};
    };
    using VAsioStream = libopenvpn::VirtualVPNAsioStream<uint8_t>;

} // namespace libopenvpn
#endif //OPENVPN_TUN_ASIO_STYLE_DEQUE_H