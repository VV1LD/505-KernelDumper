# 5.05 kernel dumper

Compile with your PC's IP listening on port 9023

On PC you can do to listen:
	socat - tcp-listen:9023 > kernelDump.bin

and to send:
	socat -u FILE:payload.bin TCP:"PS4 IP":9020

you can then trim out the socket prints or you can adapt it with 2 sockets, one for dumping, another for logging.

To compile for 5.05 you need to use an sdk with changes for 5.05 support, i have used https://github.com/xvortex/ps4-payload-sdk

