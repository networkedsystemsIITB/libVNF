## Kernel Module
* This module needed at the backend VNF when using load balancer example and the backend uses kernel stack. 
* Do the following changes in lb_module.c
    * Change the IP in line no: 638 to your LB IP
    * Set the LB IP string length as the second argument of the function (which is 12 in our case) in line no: 671
    * Change 5000 to the VNF port number on line no: 670 
* We plan to provide a config file for this soon.

* Now run the following commands:
    * make clean
    * make
    * sudo insmod lb_module.ko

* This would insert the module on the backend. To use the backend without the LB remove the module using:
    * sudo rmmod lb_module
