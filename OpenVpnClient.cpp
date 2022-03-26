#include <stdlib.h> // for atoi

#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include "OpenVpnClient.hpp"

#include "VirtualTun.h"
#include "VirtualVPNAsioStream.h"
#include "tins/tcp_ip/stream_follower.h"
#include "tins/tins.h"
#include "OpenVPNUtils.h"
#include <memory>
using namespace openvpn;
using namespace libopenvpn;

void writeMessage(std::shared_ptr<VAsioStream> vAsioStream)
{
	//uint8_t t[] = {69, 0, 0, 52, 141, 55, 64, 0, 64, 6, 30, 57, 192, 168, 7, 1, 192, 168, 7, 2, 136, 216, 0, 80, 133, 16, 10, 46, 0, 0, 0, 0, 128, 2, 114, 16, 85, 70, 0, 0, 2, 4, 5, 180, 1, 1, 4, 2, 1, 3, 3, 7};
	//size_t size = (sizeof t / sizeof t[0]); // size == 5
	//uint8_t c[] = {69, 0, 0, 72, 203, 203, 64, 0, 64, 17, 163, 146, 192, 168, 255, 18, 10, 139, 1, 1, 221, 255, 0, 53, 0, 52, 174, 21, 221, 124, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 99, 104, 97, 116, 45, 48, 4, 99, 111, 114, 101, 10, 107, 101, 121, 98, 97, 115, 101, 97, 112, 105, 3, 99, 111, 109, 0, 0, 28, 0, 1};
	//size_t sizec = (sizeof c / sizeof c[0]); // size == 5
	/*
	auto m = pkt.serialize();
	uint8_t *message = m.data();
	int length = m.size();
	
	for (int i = 0; i < length; i++)
	{
		printf("%x ", message[i]);
	}
	printf("\n");
	std::cout << "length: " << length << std::endl;
	*/
	while (true)
	{
		//std::cout << "gonna write message to s " << " of size " << length << std::endl;
		//std::cout << "gonna write message " << " of size " << sizec << std::endl;
		Tins::IP pkt = Tins::IP("10.139.1.1") /
					   Tins::TCP(80) /
					   Tins::RawPDU("I'm a payload!");
		pkt.src_addr("192.168.255.12");

		auto m = pkt.serialize();
		uint8_t *message = m.data();
		int length = m.size();
		std::cout << "SHOULD BE!!!: " << std::endl;
		for (int i = 0; i < length; i++)
		{
			printf("%x ", message[i]);
		}
		std::cout << "packet END " << std::endl;
		auto b = libopenvpn::Buffer<uint8_t>::copyFromBuffer(message, length);
		std::cout << "PACKET!!!: " << std::endl;
		for (int i = 0; i < length; i++)
		{
			printf("%x ", b.data()[i]);
		}
		std::cout << "packet END " << std::endl;
	
		vAsioStream->queue_write_some(b);
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
}


int main(int argc, char *argv[])
{
	std::cout << "libopenvpn_example" << std::endl;

	auto vAsioStream = std::make_shared<VAsioStream>();
	std::thread t(writeMessage, vAsioStream);

	int ret = 0;

	try
	{
		OpenVPNClient::init_process();
		auto orwellOpenVPNClient = build_openvpn_client_from_profile_path("../ORWELL_ZAINCO.ovpn", vAsioStream);
		Status connect_status = orwellOpenVPNClient->connect();
		if (connect_status.error)
		{
			std::cout << "connect error!: ";
			if (!connect_status.status.empty())
				std::cout << connect_status.status << ": ";
			std::cout << connect_status.message << std::endl;
		}
		//start thread here
		//ret = openvpn_client(argc, argv, nullptr, MyVirtualVPNAsioStream);
		getchar();
	}
	catch (const std::exception &e)
	{
		std::cout << "Main thread exception: " << e.what() << std::endl;
		ret = 1;
	}
	OpenVPNClient::uninit_process();
	return ret;
}