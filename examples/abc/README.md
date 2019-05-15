# Structure of ABC Example
* `local` and `remote` dirs both have code for the same A B & C components
* As the names suggest
    * `local` dir has code to run A B & C components on single machine (over kernel stack only)
    * `remote` dir has code to to run A B & C components on different machines (over both kernel and kernel-bypass stacks)
