# True libopenvpn client

Use OpenVPN as a true library, no TUN/TAP system calls.

# How it works?

Official OpenVPN3 app only knows about IP packets, it does not know how to transport TCP packets. So, everything is done through a TUN interface that it opens in the operating system. This library provides a client implementation that creates a virtual TUN, that is, a class that can simulate how a TUN works. Therefore, you can do whatever you want and transport your own IP packets. I used OpenVPN3 as a dependency, so no patches are needed, I just built upon it.

# Rust interface

For a Rust interface, look at https://github.com/lattice0/true_libopenvpn3_rust. I use Rust because I plug the https://github.com/smoltcp-rs/smoltcp library, which is a TCP stack that can be plugged together with this library so we can finally send regular TCP/UDP packets, and thus send things like HTTP requests.

# Contributing

I need to bump to the latest OpenVPN3, and also make some things more readable, as well as remove libtins dependency. PRs are welcome!
