rm server
rm server.o

g++ -fpermissive -g -I ../../include -I /home/rahul2514888/Downloads/MTP/netmap-master/sys -std=c++11 -o server.o -c server.cpp
echo "Server done"
g++ -g -o server server.o ../../mtcp_lib.o -pthread
sudo gdb ./server 9999
