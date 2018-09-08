portscanner: main.o utils.o SynScanner.o TcpScanner.o UdpScanner.o StealthScanner.o
	g++ main.o utils.o SynScanner.o TcpScanner.o UdpScanner.o StealthScanner.o -o portscanner -pthread

main.o: main.cpp
	g++ -c main.cpp

utils.o: utils.cpp
	g++ -c utils.cpp

SynScanner.o: SynScanner.cpp
	g++ -c SynScanner.cpp

TcpScanner.o: TcpScanner.cpp
	g++ -c TcpScanner.cpp

UdpScanner.o: UdpScanner.cpp
	g++ -c UdpScanner.cpp

StealthScanner.o: StealthScanner.cpp
	g++ -c StealthScanner.cpp

clean:
	rm *.o portscanner
