rm mtcp_hss
rm mtcp_hss.o


#G++ = g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -std=c++0x -std=c++11 -std=gnu++0x -ggdb
make
#g++ -fpermissive -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o utils.o -c utils.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o security.o -c security.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o packet.o -c packet.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o s1ap.o -c s1ap.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o gtp.o -c gtp.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o sip.o -c sip.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o uecontext.o -c uecontext.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o telecom.o -c telecom.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o diameter.o -c diameter.cpp
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o mysql.o -c mysql.cpp
cp ../mme_17_july//mtcp_old/mtcp_lib.o .
#packet.o utils.o s1ap.o gtp.o diameter.o sip.o uecontext.o telecom.o  security.o -lcrypto -o pcscf
g++ -fpermissive -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o kb_mme.o  -c kb_mme.cpp  
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I include -I /home/akash/netmap/sys -std=c++11 -o b.o -c b.cpp 
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -fpermissive -g -I include -I /home/sgw/Downloads/MTP/netmap-master/sys -std=c++11 -o mtcp_pcscf.o  -c mtcp_pcscf.cpp   utils.o 
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -I ../../include -I /home/sink/Downloads/MTP/netmap-master/sys -std=c++11 -o server_locking.o -c server_locking.cpp
echo "Server done"
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -g -o mme mme.o lib.o mtcp_lib.o diameter.o gtp.o network.o packet.o s1ap.o security.o sync.o telecom.o utils.o -pthread -lboost_serialization
g++ -fpermissive -std=c++0x -std=c++11 -std=gnu++0x -ggdb -o kb_mme diameter.o gtp.o my_mme.o network.o packet.o s1ap.o sctp_client.o sctp_server.o security.o sync.o telecom.o udp_client.o utils.o kb_mme.o mtcp_lib.o -lcrypto -pthread
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -o server_rss server_rss.o ../../mtcp_lib.o -pthread
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -o server_locking server_locking.o ../../mtcp_lib.o -pthread
#sudo gdb ./server_rss 9999










#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -fpermissive -lpthread  -std=c++11 -g -I include  -c testserver.cpp  -o testserver.o 
#echo "CLient done"
#g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -std=c++11 -g -o testserver testserver.o ../mtcp_lib.o -lpthread 
#sudo gdb ./client 10.129.26.73 9999
