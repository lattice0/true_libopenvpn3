//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Client tun interface for Linux.

#ifndef OPENVPN_TUN_VIRTUAL_TUN_H
#define OPENVPN_TUN_VIRTUAL_TUN_H
#include <openvpn/asio/asioerr.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/tun/builder/setup.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/persist/tunpersist.hpp>
#include "VirtualVPNAsioStream.h"
#include <openvpn/tun/extern/config.hpp>
#include "SimplePacketCrafter.h"
//#include <openvpn/tun/linux/client/tunmethods.hpp>

namespace openvpn
{
    namespace VirtualTun
    {
        //typedef AsioStyleDeque<> libopenvpn::VAsioStream;
        /*
        // Factory for tun interface objects.
        struct Factory: public TunClientFactory
        {
            typedef RCPtr<TunClientFactory> Ptr;

            virtual TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io_context,
                                                    TunClientParent &parent,
                                                    TransportClient *transcli)
            {

            }

        };
        */
        struct PacketFrom
        {
            typedef std::unique_ptr<PacketFrom> SPtr;
            BufferAllocated buf;
        };
        /*
            Can be created with `new SharedPointerHolder(my_shared_ptr)` and can be
            deleted without the shared_ptr being deleted. Thus we can pass to TunIO.
            This is needed because TunIO requires a STREAM* and deletes it in the end. 
            However I want to use to shared_ptr to libopenvpn::VAsioStream for obvious reasons. 
            TODO: try to get shared_ptr working inside TunIO, maybe change source and push request
        */
        template <class T>
        class SharedPointerHolder
        {
        public:
            SharedPointerHolder(std::shared_ptr<T> p) : p(p)
            {
            }

            template <typename MutableBufferSequence, typename ReadHandler>
            void async_read_some(
                const MutableBufferSequence &buffers,
                ReadHandler &&handler)
            {
                p->async_read_some(buffers, std::move(handler));
            }

            ~SharedPointerHolder()
            {
                //std::cout << "deleting SharedPointerHolder" << std::endl;
            }

            template <typename ConstBufferSequence>
            std::size_t write_some(
                const ConstBufferSequence &buffers)
            {
                return p->write_some(buffers);
            }

            void cancel()
            {
                p->cancel();
            }

            void release()
            {
                p->release();
            }

            void close()
            {
                p->close();
            }

        private:
            std::shared_ptr<T> p;
        };
        template <typename ReadHandler>
        class Tun : public TunIO<ReadHandler, PacketFrom, SharedPointerHolder<libopenvpn::VAsioStream>>
        {
            typedef TunIO<ReadHandler, PacketFrom, SharedPointerHolder<libopenvpn::VAsioStream>> Base;

        public:
            typedef RCPtr<Tun> Ptr;

            Tun(openvpn_io::io_context &io_context,
                ReadHandler read_handler_arg,
                const Frame::Ptr &frame_arg,
                const SessionStats::Ptr &stats_arg,
                const int socket,
                const std::string &name,
                std::shared_ptr<libopenvpn::VAsioStream> vAsioStream,
                std::string replacementIpv4,
                std::string replacementIpv6)
                : Base(read_handler_arg, frame_arg, stats_arg), vAsioStream(vAsioStream)
            {
                Base::name_ = name;
                Base::retain_stream = true;
                //Base is responsible for destroying our SharedPointerHolder
                Base::stream = new SharedPointerHolder<libopenvpn::VAsioStream>(vAsioStream);
                OPENVPN_LOG_TUN(Base::name_ << " opened with replacement ipv4 " << replacementIpv4);
                OPENVPN_LOG_TUN(Base::name_ << " opened with replacement ipv6 " << replacementIpv6);
            }

            ~Tun() { Base::stop(); }

        private:
            //By keeping a copy of libopenvpn::VAsioStream, we make it live until its internal pointer (used by TunIO) lives
            std::shared_ptr<libopenvpn::VAsioStream> vAsioStream;
            std::string replacementIpv4;
            std::string replacementIpv6;
        };

        typedef TunPersistTemplate<ScopedFD> TunPersist;

        class ClientConfig : public TunClientFactory
        {
        public:
            typedef RCPtr<ClientConfig> Ptr;

            ClientConfig(const ExternalTun::Config &tunconf,
                         const OptionList &opt,
                         std::shared_ptr<libopenvpn::VAsioStream> vAsioStream,
                         std::string replacementIpv4,
                         std::string replacementIpv6) : 
                         vAsioStream(vAsioStream), 
                         replacementIpv4(replacementIpv4),
                         replacementIpv6(replacementIpv6)
            {
                this->tun_prop = tunconf.tun_prop;
                this->frame = tunconf.frame;
                this->stats = tunconf.stats;
                load(opt);
                //this->tun_persist = tunconf.tun_persist;
                //this->stop
            }

            std::string dev_name;
            int txqueuelen = 200;

            TunProp::Config tun_prop;

            int n_parallel = 8;
            Frame::Ptr frame;
            SessionStats::Ptr stats;

            //TunBuilderSetup::Factory::Ptr tun_setup_factory;
            TunPersist::Ptr tun_persist;

            void load(const OptionList &opt)
            {
                // set a default MTU
                if (!tun_prop.mtu)
                    tun_prop.mtu = 1500;

                // parse "dev" option
                if (dev_name.empty())
                {
                    const Option *dev = opt.get_ptr("dev");
                    if (dev)
                        dev_name = dev->get(1, 64);
                }
            }

            static Ptr new_obj()
            {
                return new ClientConfig;
            }

            virtual TunClient::Ptr new_tun_client_obj(openvpn_io::io_context &io_context,
                                                      TunClientParent &parent,
                                                      TransportClient *transcli);

            TunBuilderSetup::Base::Ptr new_setup_obj()
            {
                throw std::runtime_error("new_setup_obj called! This shouldn't happen!");
                return nullptr;
                /*
                if (tun_setup_factory)
                    return tun_setup_factory->new_setup_obj();
                else
                    return new TunLinuxSetup::Setup<TUN_LINUX>();
                */
            }

        private:
            ClientConfig() {}
            std::shared_ptr<libopenvpn::VAsioStream> vAsioStream;
            std::string replacementIpv4;
            std::string replacementIpv6;
        };
        //template <class PacketCrafter = SimplePacketCrafter>
        class Client : public TunClient, public SimplePacketCrafter
        {
            friend class ClientConfig;                                                              // calls constructor
            friend class TunIO<Client *, PacketFrom, SharedPointerHolder<libopenvpn::VAsioStream>>; // calls tun_read_handler

            typedef Tun<Client *> TunImpl;

        public:
            virtual void tun_start(const OptionList &opt, TransportClient &transcli, CryptoDCSettings &) override
            {
                if (!impl)
                {
                    halt = false;

                    if (config->tun_persist)
                    {
                        OPENVPN_LOG("TunPersist: long-term session scope");
                        tun_persist = config->tun_persist; // long-term persistent
                    }
                    else
                    {
                        OPENVPN_LOG("TunPersist: short-term connection scope");
                        tun_persist.reset(new TunPersist(true, false, nullptr)); // short-term
                    }

                    try
                    {
                        const IP::Addr server_addr = transcli.server_endpoint_addr();
                        //socket descriptor is always 0 since we use a virtual socket that never dies
                        int sd = 0;

                        // Check if persisted tun session matches properties of to-be-created session
                        if (tun_persist->use_persisted_tun(server_addr, config->tun_prop, opt))
                        {
                            state = tun_persist->state();
                            sd = tun_persist->obj();
                            OPENVPN_LOG("TunPersist: reused tun context");
                        }
                        else
                        {
                            // notify parent
                            parent.tun_pre_tun_config();

                            // close old tun handle if persisted
                            tun_persist->close();

                            // parse pushed options
                            TunBuilderCapture::Ptr po(new TunBuilderCapture());
                            TunProp::configure_builder(po.get(),
                                                       state.get(),
                                                       config->stats.get(),
                                                       server_addr,
                                                       config->tun_prop,
                                                       opt,
                                                       nullptr,
                                                       false);

                            //Tells PacketCrafter that this is the source IPV4 to be used when crafting IP packets
                            //std::cout << "###############setSourceIPV4: " << po->vpn_ipv4()->address << std::endl;
                            if (po->vpn_ipv4())
                                SimplePacketCrafter::setSourceIPV4(po->vpn_ipv4()->address);
                            if (po->vpn_ipv6())
                                SimplePacketCrafter::setSourceIPV6(po->vpn_ipv6()->address);

                            state->iface_name = "virtual_tun";
                            tun_persist->persist_tun_state(sd, state);

                            // enable tun_setup destructor
                            //tun_persist->add_destructor(tun_setup);
                        }

                        // start tun
                        impl.reset(new TunImpl(io_context,
                                               this,
                                               config->frame,
                                               config->stats,
                                               sd,
                                               state->iface_name,
                                               vAsioStream,
                                               replacementIpv4,
                                               replacementIpv6));
                        impl->start(config->n_parallel);

                        // signal that we are connected
                        parent.tun_connected();
                    }
                    catch (const std::exception &e)
                    {
                        if (tun_persist)
                            tun_persist->close();

                        stop();
                        parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
                    }
                }
            }

            virtual bool tun_send(BufferAllocated &buf) override
            {
                return send(buf);
            }

            virtual std::string tun_name() const override
            {
                if (impl)
                    return impl->name();
                else
                    return "UNDEF_TUN";
            }

            virtual std::string vpn_ip4() const override
            {
                if (state->vpn_ip4_addr.specified())
                    return state->vpn_ip4_addr.to_string();
                else
                    return "";
            }

            virtual std::string vpn_ip6() const override
            {
                if (state->vpn_ip6_addr.specified())
                    return state->vpn_ip6_addr.to_string();
                else
                    return "";
            }

            virtual std::string vpn_gw4() const override
            {
                if (state->vpn_ip4_gw.specified())
                    return state->vpn_ip4_gw.to_string();
                else
                    return "";
            }

            virtual std::string vpn_gw6() const override
            {
                if (state->vpn_ip6_gw.specified())
                    return state->vpn_ip6_gw.to_string();
                else
                    return "";
            }

            virtual void set_disconnect() override
            {
            }

            virtual void stop() override { stop_(); }
            virtual ~Client() { stop_(); }

        private:
            Client(openvpn_io::io_context &io_context_arg,
                   ClientConfig *config_arg,
                   TunClientParent &parent_arg,
                   std::shared_ptr<libopenvpn::VAsioStream> vAsioStream,
                   std::string replacementIpv4,
                   std::string replacementIpv6)
                : io_context(io_context_arg),
                  config(config_arg),
                  parent(parent_arg),
                  vAsioStream(vAsioStream),
                  replacementIpv4(replacementIpv4),
                  replacementIpv6(replacementIpv6),
                  state(new TunProp::State()),
                  halt(false)
            {
            }

            void dump(Buffer &buf) {
                for (size_t i =0; i<buf.size(); i++) {
                    //std::cout << static_cast<char*>(buf.data());
                    std::cout << buf.data()[i];
                }
                std::cout << std::endl;
            }

            //sends back from the vpn server to the client
            bool send(Buffer &buf)
            {
                if (impl) {
                    //BIG TODO: will always Buffer buf have an entire IP packet so we can always replace the IP?
                    if (replacementIpv4.empty()) {
                        throw std::runtime_error("replacementIpv4 for SimplePacketCrafter is empty");
                    }
                    SimplePacketCrafter::replaceDestinationAddress(buf.data(), buf.size(), replacementIpv4, replacementIpv6);
                    return impl->write(buf);
                }
                else
                    return false;
            }

            void tun_read_handler(PacketFrom::SPtr &pfp) // called by TunImpl
            {
                /*
                    OpenVPN3 server only forwards packets with the rigth source IP, which
                    is the one given by OpenVPN3 client in the tun creation process. However 
                    since we're using virtual tun we have to do it by ourselves.
                */
                SimplePacketCrafter::fillIPSource(pfp->buf);
                parent.tun_recv(pfp->buf);
            }

            void tun_error_handler(const Error::Type errtype, // called by TunImpl
                                   const openvpn_io::error_code *error)
            {
            }

            void stop_()
            {
                if (!halt)
                {
                    halt = true;

                    // stop tun
                    if (impl)
                        impl->stop();

                    tun_persist.reset();
                }
            }

            openvpn_io::io_context &io_context;
            std::shared_ptr<libopenvpn::VAsioStream> vAsioStream;
            std::string replacementIpv4;
            std::string replacementIpv6;
            TunPersist::Ptr tun_persist;
            ClientConfig::Ptr config;
            TunClientParent &parent;
            typename TunImpl::Ptr impl;
            TunProp::State::Ptr state;
            TunBuilderSetup::Base::Ptr tun_setup;
            bool halt;
        };

        inline TunClient::Ptr ClientConfig::new_tun_client_obj(openvpn_io::io_context &io_context,
                                                               TunClientParent &parent,
                                                               TransportClient *transcli)
        {
            return TunClient::Ptr(new Client(io_context, this, parent, vAsioStream, replacementIpv4, replacementIpv6));
        }

    } // namespace VirtualTun
} // namespace openvpn

#endif // OPENVPN_TUN_VIRTUAL_TUN_H
