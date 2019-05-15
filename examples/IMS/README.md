## IP Multimedia Subsystem [IMS]
* This is the kernel version of IMS ported to use the **libvnf** library
* This has five components `ran`, `pcscf`, `icscf`, `hss`, `scscf`
* The packet flow is as below
   * ran --> pcscf --> icscf --> hss --> icscf --> scscf --> hss --> scscf --> icscf --> pcscf --> ran

### Preparation 
* Setup each component on separate VMs.
* In each of these directories, there is a file **commons.h** which has the IPs of each component. Change these to the correct ones as per your VM IPs.
* Install the following dependencies:
    * libssl in Ubuntu distribution of linux you can install using: `sudo apt-get install libssl-dev`
    * libboost in Ubuntu distribution of linux you can install using: `sudo apt-get install libboost-all-dev`


### How to Compile?
* To compile the IMS components and link it with libvnf
    * **libvnf** needs to be installed into system in kernel stack
    * Setup **libvnf** as mentioned in [README.md](../../README.md) at the project root using kernel stack
* Go inside each directories and run the following command
  *  `make clean && make`
* This will create the executables **hss**, **icscf**, **pcscf**, **ransim.out**, **scscf** respectively in the corresponding directories. 

### How to run?
* After compilation, execute
    * `ulimit -n 65535` as root user on A, B & C VMs
    * `echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse` as root user on A, B & C VMs
* We need to first start the following 4 components:
    * **hss**: go into the corresponding directory and run :
        * `./hss`
    * **icscf**: go into the corresponding directory and run :
        * `./icscf`
    * **pcscf**: go into the corresponding directory and run :
        * `./pscscf`
    * **scscf**: go into the corresponding directory and run :
        * `./scscf`

* Now after all the four components are up and running, Go into the **ran** directory and run:
    * `./ransim.out <no-threads> <no-seconds>`, where
        * `<no-threads>` is the number of threads used by **ran** node
        * `<no-seconds>` is the number of seconds the **ran** node stays alive
