First Heap Exploitation

Idea: 
	Essentially we get the forward pointer address to the glibc arena from doing a double free on an unsorted bin, and but we dont need that address to calculate anything on our stack but rather calculate the target using the main_arena to overwrite our free hook and launch a shell. Main arena gives us glibc start which gives us free hook and system sh.

Taking a look at the source code, we can see that we are able to allocate more then 0x70 bytes of data (0x700). This is useful in leaking the heap address. 

Best if you use glibc 2.27 and link the binary as this will make your life alot easier. 

![Kiku](/screenshot_whoami.png)

***
This problem is a spinoff of UD CTF Babyjeep
*** 