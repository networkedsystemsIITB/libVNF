# Structure of Evolved Packet Core Example
* The EPC contains 5 components `ran`, `mme`, `hss`, `sgw` and `pgw`
* The packet flow is as shown below
  * initial attach and authentication: ran --> mme --> hss --> mme --> ran
  * session setup: ran --> mme --> sgw --> pgw --> sgw --> mme --> ran
* `mme` is built using libvnf
* `ran`, `hss`, `sgw`, `pgw` components of epc are built without libvnf
* These components are built over the kernel-bypass stack

# Preparation
* To install openSSL: `sudo apt-get install libssl-dev`
* Change the **MTCP_FLD** and **UTIL_FLD** in each component's Makefile to point to the corresponding subfolders (mtcp and util) inside your `mtcp-master` folder. 
* Change the IP addresses in `defport.h` in each componenet 
* Changes required in **server.conf**
  * port=<network_interface_name>
  * num_cores=<number_of_cores_of_your_VM>
* To compile the mme and link it with libvnf
    * **libvnf** needs to be installed into system with the kernel-bypass stack option
    * Setup **libvnf** as mentioned in [README.md](../../README.md) at the project root using kernel stack
 
# How to Compile
* RAN: `make clean && make ransim.out`
* MME: `make clean && make`
* HSS: `make clean && make hss`
* SGW: `make clean && make sgw`
* PGW: `make clean && make pgw`

# How to run
* Start all the VNFs in following order 
  * MME: `sudo ./mme`
  * HSS: `./hss.out 50`
  * SGW: `sudo ./sgw_kby`
  * PGW: `sudo ./pgw_kby`
  * RAN: `./ransim.out 1 60` where the first argument is no.of RAN threads and second is duration of experiment
