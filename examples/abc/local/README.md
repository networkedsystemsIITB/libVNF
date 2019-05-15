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

## How to Compile?
* Setup for **libvnf** is [README.md](../../../README.md) at the project root
* Compile A node using
    * `make a`
* Similarly compile C node using
    * `make c`
* To compile node B and link with libvnf
    * **libvnf** needs to be installed into system
    * Setup **libvnf** as mentioned in [README.md](../../../README.md) at the project root using kernel stack
    * on kernel stack statically use `make b-kernel-static`
    * on kernel stack dynamically use `make b-kernel-dynamic`
       * In this case also add /usr/local/lib to $LD_LIBRARY_PATH `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`
* Running `make` will create `a` `b-kernel-static` & `c` executables

## How to run?
* After compilation, run
    * `ulimit -n 65535` as root
    * `echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse` as root
* First, start C node using `./c`
* Then, start B node using `sudo ./b-kernel-{static/dynamic}`
* Finally, start A node using `./a <no-threads> <no-seconds>`, where
    * `<no-threads>` is the number of threads used by A node
    * `<no-seconds>` is the number of seconds the A node stays alive
