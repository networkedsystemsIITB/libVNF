## ABC Network
* ABC network is a demonstrating example of **libvnf**
* There are three network functions or nodes in this example named A, B & C
* The nodes are connected as shown below
    * A --- B --- C
* The packet flow is as follows
    * Node A sends request to Node B
    * Node B contacts Node C to fetch some data
    * Node C replies back to Node B
    * Node B then replies back to A with the response from Node C
    * And this repeats
* This models a common client-server-database architecture
* Node B is build using **libvnf**

## Preparation
* VM = Virtual Machine
* We will assume that A, B & C are in three different VMs in this example
* Preparation
    * For Node A, in [a.cpp](a.cpp) change the `SERVER_IP` as B VM IP address and `CLIENT_IP` as A VM IP address
    * For Node C, in [c.cpp](c.cpp) change the variable `my_ip` to C VM IP address
    * For Node B, in [b.cpp](b.cpp)
        * Change the following variables in main function
           * `mme_ip` = B VM IP address
           * `neighbour1_ip` = C VM IP address
* In [Makefile](Makefile) change `MTCP_P_FLD` macro to mTCP path
* mTCP configuration needs a **server.conf** file
* Changes required in **server.conf**
    * **port=<network_interface_name>**
    * **num_cores=<number_of_cores_of_your_VM>**

## How to Compile?
* Compile node A using `make a`
* Similarly Compile node C using `make c`
* To compile node B and link with libvnf
    * **libvnf** needs to be installed into system in appropriate stack
    * Setup **libvnf** as mentioned in [README.md](../../../README.md) at the project root using appropriate stack
    * on kernel stack statically use `make b-kernel-static`
    * on kernel stack dynamically use `make b-kernel-dynamic`
       * In this case also add /usr/local/lib to $LD_LIBRARY_PATH `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`
    * on kernel-bypass stack statically use `make b-kernelbypass-static`
    * on kernel-bypass stack dynamically use `make b-kernelbypass-dynamic`
       * In this case also add /usr/local/lib to $LD_LIBRARY_PATH `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`

## How to run?
* After compilation, execute
    * `ulimit -n 65535` as root user on A, B & C VMs
    * `echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse` as root user on A, B & C VMs
* First, start C node using `./c`
* Then, start B node using `sudo ./b-{kernel/kernelbypass}-{static/dynamic}`
* Finally, start A node using `./a <no-threads> <no-seconds>`, where
    * `<no-threads>` is the number of threads used by A node
    * `<no-seconds>` is the number of seconds the A node stays alive
