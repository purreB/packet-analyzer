# packet-analyzer
A packet analyzer built in Python for analyzing recorded / intercepted network traffic on a client.
This can be useful when you do not have accsess to a GUI such as wireshark or otherwise just want to programmatically process a pcap file.

#You can filter through:
* Specific ip adresses
* Packet types
* Specific time it took for a TCP SYN-ACK handsake after initial SYN
* Find connections that were prematurely terminated because of a RST sent by the client, this is useful because it can indicate attempts to hijack a TCP connection.
* If a RST is found, get a count of how many other connections were in progress between that client and other servers.
