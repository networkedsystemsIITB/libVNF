## Load Balancer
This can be used as a Load Balancer for the **VNF B** in the **[ABC example](../abc/remote)**

### Preparation
* Give the path to your Netmap folder in [CMakeLists.txt](../../CMakeLists.txt) on line 75
* This needs the **Layer3 VNF** version of the library, follow the instructions from [here](../../README.md)
* If the backend VNF is on kernel then follow the instructions from [backend_kernel_module](backend_kernel_module/README.md) to start the kernel module on the backend.
* If the backend VNF is on kernel_bypass then follow the instrucions from [mtcp_when_using_lb](https://github.com/networkedsystemsIITB/Modified_mTCP/tree/master/mtcp_when_using_lb) to use mTCP modified for LoadBalancer on the backend.
* In [load_balancer.cpp](load_balancer.cpp) do the following changes:
  * In line 243 change the first parameter to your interface name("eth5" in our case) and the second parameter to your IP address.
  * In line 248 change the string assigned to **to_send** variable to the IP address of your backend VNF.
  * You can add more backends by doing more `setData`(and incrementing its fourth parameter) and `backend_count++` after each `setData`.

### How to Compile?
* Run the following command:  `bash run.sh` 
* This will create an executable **load_balancer**

## How to run?
* Run `sudo ./load_balancer`
