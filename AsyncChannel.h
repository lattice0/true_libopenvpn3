#ifndef LIB_OPEN_VPN_ASYNC_CHANNEL_H
#define LIB_OPEN_VPN_ASYNC_CHANNEL_H

#include <queue>
#include <mutex>
#include <future>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <optional>
#include <chrono>

template <class Reader, class Buffer>
class AsyncChannel
{
public:
    AsyncChannel(bool startTaskExecutor)
    {
        if (startTaskExecutor)
            tasksThread = std::thread(&AsyncChannel::taskExecutor, this);
    }

    ~AsyncChannel()
    {
        //Blocks until taskExecutor loop stops. It's not good to block but what can I do?
        stop();
        if (tasksThread.joinable())
            tasksThread.join();
    }

    //Read call, to be filled with a buffer
    void emplace_reader(std::shared_ptr<Reader> reader)
    {
        {
            std::unique_lock<std::mutex> lock{readerMutex};
            //std::cout << "emplacing reader with size " << reader->size() << std::endl;
            readerFifo.emplace(reader);
        }
        tasksConditionVariable.notify_all();
    }
    //Buffer that fills read call
    void emplace_buffer(Buffer buffer)
    {
        {
            std::unique_lock<std::mutex> lock{bufferMutex};
            bufferFifo.emplace(buffer);
        }
        tasksConditionVariable.notify_all();
    }

    //Direct read, without queueing a read handler
    std::optional<Buffer> read_all()
    {
        throw std::runtime_error("read_all deprecated");
        {
            std::unique_lock<std::mutex> bufferLock{bufferMutex};
            if (!bufferFifo.empty())
            {
                auto b = bufferFifo.front();
                bufferFifo.pop();
                return b;
            }
            else
            {
                return std::nullopt;
            }
        }
    }

    //Direct read, without queueing a read handler
    bool read_just(size_t just, std::function<void(uint8_t*, uint8_t*)> onConsume)
    {
        std::unique_lock<std::mutex> bufferLock{bufferMutex};
        if (!bufferFifo.empty())
        {
            //b is a reference
            auto b = bufferFifo.front();
            //Consumes up to `just` bytes from `b`
            size_t n = b.consume(just, onConsume);
            if (!b.stillHasData()) {
                //we can pop, because we consumed the entire buffer
                bufferFifo.pop();
            } else {
                //no pop, because there is more to consume
            }
            //returns true because we consumed the buffer
            return true;
        }
        else
        {
            //returns false because we did not consume the buffer
            return false;
        }
    }

    void stop()
    {
        shouldContinue.store(false);
    }

    void taskExecutor()
    {
        while (shouldContinue.load())
        {
            using namespace std::chrono_literals;
            std::unique_lock<std::mutex> lock{tasksMutex};
            tasksConditionVariable.wait_for(lock, 35ms);
            {
                if (!readerFifo.empty() && !bufferFifo.empty())
                {
                    auto r = readerFifo.front();
                    auto b = bufferFifo.front();

                    //Tries to consume, from `b`, `r->size()` bytes
                    size_t amountConsumed = b.consume(r->size(), [&r](const uint8_t* begin, const uint8_t* end){
                        //The amount consumed from `b`
                        size_t n = end-begin;
                        //Fills r with `n` bytes from `b`
                        r->receive(begin, n);
                    });
                    if (!b.stillHasData()) {
                        //We consumed everything from `b`, we can pop `b` (`r` is always popped)
                        bufferFifo.pop();
                        readerFifo.pop();
                    } else {
                        //There's more to consume from `b`, we cannot pop `b`
                        readerFifo.pop();
                    }
                    //Deliver the buffer to the reader
                    r->deliver();
                }
            }
        }
    }

private:
    //TODO: add size control to these queues so it won't eat all RAM in case reader or buffer stops emplacing
    std::queue<Buffer> bufferFifo;
    std::queue<std::shared_ptr<Reader>> readerFifo;
    std::mutex tasksMutex;
    std::thread tasksThread;
    std::condition_variable tasksConditionVariable;
    std::mutex bufferMutex;
    std::mutex readerMutex;
    std::atomic<bool> shouldContinue{true};
};
#endif //LIB_OPEN_VPN_ASYNC_CHANNEL_H