all: rawhttpget

rawhttpget: TcpPacket.cpp TcpHeader.cpp IpHeader.cpp rawhttpget.cpp
	g++ TcpPacket.cpp TcpHeader.cpp IpHeader.cpp rawhttpget.cpp -o rawhttpget

clean:
	rm -rf *o rawhttpget

