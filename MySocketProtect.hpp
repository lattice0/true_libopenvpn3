#ifndef MY_SOCKET_API
#define MY_SOCKET_API
#include "OpenVPNClientBase.hpp"
#include <openvpn/transport/socket_protect.hpp>
namespace openvpn
{
	class MySocketProtect : public SocketProtect
	{
	public:
		MySocketProtect() : parent(nullptr) {}

		void set_parent(libopenvpn::OpenVPNClientBase *parent_arg)
		{
			parent = parent_arg;
		}

		bool socket_protect(int socket, IP::Addr endpoint) override
		{
			if (parent)
			{
#if defined(OPENVPN_COMMAND_AGENT) && defined(OPENVPN_PLATFORM_WIN)
				return WinCommandAgent::add_bypass_route(endpoint);
#elif defined(OPENVPN_COMMAND_AGENT) && defined(OPENVPN_PLATFORM_MAC)
				return UnixCommandAgent::add_bypass_route(endpoint);
#else
				return parent->socket_protect(socket, endpoint.to_string(), endpoint.is_ipv6());
#endif
			}
			else
				return true;
		}

		void detach_from_parent()
		{
			parent = nullptr;
		}

	private:
		libopenvpn::OpenVPNClientBase *parent;
	};
} // namespace openvpn
#endif