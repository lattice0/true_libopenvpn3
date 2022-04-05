# True libopenvpn client

Use OpenVPN as a true library, no TUN/TAP system calls.

# How it works?

Official OpenVPN3 app only knows about IP packets, it does not know how to transport TCP packets. So, everything is done through a TUN interface that it opens in the operating system. This library provides a client implementation that creates a virtual TUN, that is, a class that can simulate how a TUN works. Therefore, you can do whatever you want and transport your own IP packets. I used OpenVPN3 as a dependency, so no patches are needed, I just built upon it.

You need a TCP/IP stack, otherwise because this library is only concerned with transporting IP packets. Since there is no decent userspace stack in C/C++, I'm using Rust's smoltcp on my projects.

# Why?

This library is useful because you don't need privileged capabilities to create/access tun/tap interfaces, so you can support OpenVPN connections on your app on Android for example without requiring VPN permissions. Also, you can connect to multiple OpenVPN servers through multiple profiles and send packets through them on Android, where traditionally it would let you have just one connection at the same time.

# Rust interface

For a Rust interface, look at https://github.com/lattice0/true_libopenvpn3_rust. I use Rust because I plug the https://github.com/smoltcp-rs/smoltcp library, which is a TCP stack that can be plugged together with this library so we can finally send regular TCP/UDP packets, and thus send things like HTTP requests.

# Contributing

I need to bump to the latest OpenVPN3, and also make some things more readable, as well as remove libtins dependency. PRs are welcome!

TODO:

- bump to latest openvpn3
- clean lots of stuff
- remove libtins dependency (it's only used for generating an IP address lol)
- fix proton vpn android compilation (test on android, and possibly make iOS work too from the proton ios app)
