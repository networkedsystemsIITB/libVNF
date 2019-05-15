# libvnf
* **libvnf** is a library to easily build custom, scalable, high-performance, virtual network functions
* This is an implementation of paper [libVNF: Building Virtual Network Functions Made Easy](https://www.cse.iitb.ac.in/~mythili/research/papers/2018-libvnf-socc.pdf) accepted in SoCC 2018

### Features
* Written entirely in C++
* Aims to reduce lines of code without compromising on performance
* Has a non-blocking event-driven architecture
* Supports building of transport layer end-point VNFs as well as L2/L3 VNFs
* Supports kernel and kernel-bypass stacks \[chosen at compile time\]
* API is stack agnostic => No change in code when stack changes

# Navigating Repo
* The headers are in [include](include) directory
* The implementations are in [src](src) directory
* Example VNFs that use **libvnf** are provided in [examples](examples) dir
* Custom dependencies are listed in [dependencies](dependencies) dir

# How to Use?
* **libvnf** can be installed directly into the system using cmake

## Dependencies
* Before installation, the following dependencies need to be satisfied
    * cmake version >= 3.5.0
    * Kernel Stack
        * boost (libboost-all-dev)
    * Kernel-bypass stack
        * boost (libboost-all-dev)
        * mTCP
        * netmap + vale switch
        * dpdk
        * numa (libnuma-dev)
        * Installation instructions can be found at [dependencies/kernel_bypass_stack](dependencies/kernel_bypass_stack)
    * Layer3 VNF
        * boost (libboost-all-dev)
        * Netmap uses vale as the software switch. Follow steps (1-4) from [here](https://github.com/networkedsystemsIITB/Modified_mTCP/blob/master/mTCP_over_Netmap/docs/netmap_docs/user_manual.pdf)


## Installation
* In case of kernel bypass setup give the path to your mTCP folder in [CMakeLists.txt](CMakeLists.txt) on line 50, 51
* In [project root directory](.) execute the following
    * `mkdir build`
    * `cd build`
    * `cmake .. -DSTACK=KERNEL` or `cmake .. -DSTACK=KERNEL_BYPASS` or `cmake .. -DSTACK=L3VNF` 
    * `make`
    * `sudo make install`
* This creates and installs
    * a shared object (.so) version for of libvnf dynamic linking
    * an archive (.a) version of libvnf for static linking
* Dynamically linkable version of library will be named **libvnf-{kernel/kernelbypass/l3}-dynamic.so**
* Statically linkable version will be named **libvnf-{kernel/kernelbypass/l3}-static.a**
* CMake caches the options passed to it, so once passed there is no need to pass the option (-DSTACK=...) from second time
* If you want to change the stack, delete all files in `build` dir and run cmake again with required stack

## Initialization
* The following function in the library should be called before starting any VNF
    * `int initLibvnf(int _maxCores, int _bufferSize, string _dataStoreIP, vector<int> _dataStorePorts, int _dataStoreThreshold, bool _useRemoteDataStore)`
* Refer to [this](examples/abc/local/b.cpp#L136) file for a concrete example

## Optional Configuration
* While building I/O intensive applications on kernel stack run
    * `ulimit -n 65535` as root
    * `echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse` as root

# Notes on Optimization
* The library is written to optimize performance throughput
* To achieve maximum possible performance make sure to use `-O3` when compiling your VNF

# Collaborators
1. [Priyanka Naik](https://www.cse.iitb.ac.in/~ppnaik/)
1. [Akash Kanase](https://in.linkedin.com/in/akashkanase)
1. [Trishal Patel](https://www.cse.iitb.ac.in/~trishal/)
1. [Yashasvi Sriram Patkuri](https://github.com/Yashasvi-Sriram)
1. [Sai Sandeep Moparthi](https://github.com/sandeep-END)
1. [Sagar Tikore](https://www.cse.iitb.ac.in/~sagart/)
1. [Vaishali Jhalani](https://www.cse.iitb.ac.in/~vaishali/)
1. [Prof. Mythili Vutukuru](https://www.cse.iitb.ac.in/~mythili/)
