
#-----------------Compiler------------------#

G++ = g++ -std=c++0x -std=c++11 -std=gnu++0x -ggdb -O3 -fpermissive -Wno-narrowing

#-------------------------------------------#
#hss: hss.cpp hss.h packet.h diameter.h gtp.h packet.cpp packet.h s1ap.h utils.h uecontext.h packet.o utils.o sip.o uecontext.o 
#	$(G++) hss.cpp packet.o utils.o s1ap.o gtp.o diameter.o sip.o  uecontext.o -o hss
	
all: hss

uecontext.o: uecontext.cpp uecontext.h
	$(G++)  -c -o uecontext.o  uecontext.cpp

packet.o: packet.cpp packet.h utils.h sip.h
	$(G++) -c -o packet.o packet.cpp

sip.o: sip.cpp sip.h
	$(G++) -c -o sip.o sip.cpp

utils.o: utils.cpp utils.h packet.h packet.cpp
	$(G++) -c utils.cpp -o utils.o 

security.o: packet.h security.cpp security.h utils.h
	$(G++) -c -o security.o security.cpp -lcrypto

sync.o: sync.cpp sync.h utils.h
	$(G++) -c -o sync.o sync.cpp

telecom.o: telecom.cpp telecom.h utils.h
	$(G++) -c -o telecom.o telecom.cpp

hss: hss.cpp hss.h utils.o sip.o uecontext.o packet.o security.o sync.o telecom.o
	$(G++) hss.cpp utils.o sip.o uecontext.o packet.o security.o sync.o telecom.o -lvnf-kernel-static -lcrypto -pthread -lboost_system -lboost_serialization -o hss

clean:
	rm -f hss *~ *.o *.out

#--------------Special Commands-------------#

# make -k (To keep going on even after encountering errors in making a former target)

#-------------------------------------------#
