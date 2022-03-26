#ifndef LIB_OPEN_VPN_ASIO_ASYNC_CHANNEL_H
#define LIB_OPEN_VPN_ASIO_ASYNC_CHANNEL_H
#include <memory>
#include <functional>
namespace libopenvpn
{
    template <class T>
    class Buffer
    {
    public:

        Buffer(size_t reserve) {
            _buffer.reserve(reserve);
        }

        static Buffer<T> copyFromBuffer(const uint8_t* buffer, size_t size) {
            auto b = Buffer(size);
            b.write(buffer, size);
            return std::move(b);
        }

        void write(const T* buffer, size_t amountToWrite) {
            this->_buffer.insert(this->_buffer.begin(), buffer, buffer + amountToWrite);
        }

        size_t consume(const size_t amountToConsume, std::function<void(T*, T*)> onConsume) {
            if (_current==this->_buffer.size()) {
            //this means we've already read everything. Maybe we should throw or just return 0?
            return 0; 
            }

            size_t currentActualSize = this->_buffer.size() - this->_current;
            if (amountToConsume <= currentActualSize) {
                onConsume(this->_buffer.data() + this->_current, this->_buffer.data() + this->_current + amountToConsume);
                this->_current += amountToConsume;
                return amountToConsume;
            } else {
                size_t remaining = currentActualSize;
                onConsume(this->_buffer.data() + this->_current, this->_buffer.data() + this->_current + remaining);
                this->_current += remaining;
                return remaining;
            }
        }

        bool stillHasData() {
            if (_current==this->_buffer.size()) {
                return false;
            } else {
                return true;
            }
        }

        size_t consume(const size_t amountToConsume, T* bufferToWrite) {
            return consume(amountToConsume, [bufferToWrite](T* begin, T*end){
                std::copy(begin, end, bufferToWrite);
            });
        }

        size_t size() {
            return _buffer.size() - _current;
        }

    private:
        std::vector<T> _buffer;
        size_t _current = 0;
    };

    template <class T>
    class AsioReader
    {
    public:
        AsioReader()
        {
        }

        virtual ~AsioReader() {}

        virtual void receive(const T* buffer, size_t ammoutToReceive) = 0;

        virtual void deliver() = 0;

        virtual size_t size() = 0;
    };

} // namespace libopenvpn
#endif //LIB_OPEN_VPN_ASIO_ASYNC_CHANNEL_H