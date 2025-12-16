.PHONY:all
all:server client
server:server.cpp
	g++ -o $@ $^ -std=c++11
client:client.cpp
	g++ -o $@ $^ -std=c++11
.PHONY:clean
clean:
	rm -f server client