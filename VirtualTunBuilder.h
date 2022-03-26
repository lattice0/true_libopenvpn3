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

#ifndef OPENVPN_TUN_VIRTUAL_CLIENT_TUNSETUP_H
#define OPENVPN_TUN_VIRTUAL_CLIENT_TUNSETUP_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <mutex>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/to_string.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/asio/asioerr.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/builder/setup.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/netconf/linux/gw.hpp>

namespace openvpn
{
    namespace VirtualTunSetup
    {
        OPENVPN_EXCEPTION(tun_open_error);
        OPENVPN_EXCEPTION(no_socketpair_error);

        /*
OPENVPN_EXCEPTION(tun_linux_error);
OPENVPN_EXCEPTION(tun_open_error);
OPENVPN_EXCEPTION(tun_layer_error);
OPENVPN_EXCEPTION(tun_ioctl_error);
OPENVPN_EXCEPTION(tun_fcntl_error);
OPENVPN_EXCEPTION(tun_name_error);
OPENVPN_EXCEPTION(tun_tx_queue_len_error);
OPENVPN_EXCEPTION(tun_ifconfig_error);
*/

        class SocketPair
        {
        public:
            struct ConnectionException : public std::exception
            {
                const char *what() const throw()
                {
                    return "Could not open socketpair";
                }
            };

            int getSocketA()
            {
                return getSocket(0);
            }

            int getSocketB()
            {
                return getSocket(1);
            }

            ~SocketPair()
            {
                //TODO: close connection
            }

        private:
            int getSocket(int x)
            {
                std::unique_lock<std::mutex>{mutex};
                if (connected)
                {
                    return socket_vector[x];
                }
                else
                {
                    int c = connect();
                    if (!c)
                    {
                        throw ConnectionException();
                    }
                    else
                    {
                        return socket_vector[x];
                    }
                }
            }
            bool connect()
            {
                if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, socket_vector))
                {
                    connected = false;
                    return false;
                }
                else
                {
                    connected = true;
                    return true;
                }
            }
            int socket_vector[2];
            bool connected;
            std::mutex mutex;
        };

        class Setup : public TunBuilderSetup::Base
        {
        public:
            typedef RCPtr<Setup> Ptr;

            // This empty constructor shouldn't be needed, but due to a
            // plausible compiler bug in GCC 4.8.5 (RHEL 7), this empty
            // constructor is required to be able to build.  This is
            // related to the member initialization of the private
            // remove_cmds_bypass_gw and remove_cmds class members.
            Setup() {}

            Setup(SocketPair &socketPair)
            {
                //TODO?
            }

            Setup(std::shared_ptr<SocketPair> socketPair)
            {
                this->socketPair = socketPair;
            }

            struct Config : public TunBuilderSetup::Config
            {
                std::string iface_name;
                Layer layer; // OSI layer
                std::string dev_name;
                int txqueuelen;
                bool add_bypass_routes_on_establish; // required when not using tunbuilder
            };

            void destroy(std::ostream &os) override
            {
                // remove added routes
                //remove_cmds->execute(os);

                // remove bypass route
                //remove_cmds_bypass_gw->execute(os);
            }

            bool add_bypass_route(const std::string &address,
                                  bool ipv6,
                                  std::ostream &os)
            {
                /*
        // nothing to do if we reconnect to the same gateway
        if (connected_gw == address)
            return true;

        // remove previous bypass route
        remove_cmds_bypass_gw->execute(os);
        remove_cmds_bypass_gw->clear();

        ActionList::Ptr add_cmds = new ActionList();
        //TUNMETHODS::add_bypass_route(tun_iface_name, address, ipv6, nullptr, *add_cmds, *remove_cmds_bypass_gw);

        // add gateway bypass route
        add_cmds->execute(os);
        */
                std::cout << "add_bypass_route, address: " << address << " ipv6: " << ipv6 << " os: (missing)" << std::endl;
                return true;
            }

            int establish(const TunBuilderCapture &pull, // defined by TunBuilderSetup::Base
                          TunBuilderSetup::Config *config,
                          Stop *stop,
                          std::ostream &os) override
            {
                std::cout << "gonna establish file descriptor" << std::endl;
                if (socketPair)
                {
                    try
                    {
                        std::cout << "returning socket " << socketPair->getSocketA() << std::endl;
                        connected_gw = pull.remote_address.to_string();
                        return socketPair->getSocketA();
                    }
                    catch (SocketPair::ConnectionException &e)
                    {
                        throw tun_open_error();
                    }
                }
                else
                {
                    std::cout << "no socket pair!!" << std::endl;
                    throw no_socketpair_error("no socketpair shared_ptr setted");
                }
            }

        private:
            std::string connected_gw;
            std::shared_ptr<SocketPair> socketPair;
            std::string tun_iface_name; // used to skip tun-based default gw when add bypass route
        };
    } // namespace VirtualTunSetup
} // namespace openvpn

#endif // OPENVPN_TUN_VIRTUAL_CLIENT_TUNSETUP_H
