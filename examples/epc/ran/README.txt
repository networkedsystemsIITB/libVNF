Notes:
0- It runs with original mtcp, put it in mtcp-master/apps folder and extract.

1- File kb-sc/epc/defport.h contains default ports and ip addresses. Change ips here and it will reflect in include-epc folder as well as kby_mme/sgw/pgw.cpp

2- To run, first go to kb-sc-epc/include-epc folder and do "make clean" and "make". This links the required epc files to the machine which are used by kby_mme/sgw/pgw.cpp.

3- Now compile mme/sgw/pgw using make file ("make"). You may need to modify server.conf for eth before runing the components.

Thanks
Trishal