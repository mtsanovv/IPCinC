# IPCinC
A simple C program that demonstrates inter-process communication with named pipes.

## Prerequisites
- GCC compiler

## Running it
```
$ gcc -o ipcinc main.c
```

## Notes
- This was written for an assignment at my university, TU-Sofia.
- The main idea of this app was to simulate something similar to fail2ban - if a user attempts to log in too many times, their saved IP address gets graylisted/blocked. Its only purpose was to showcase operations with named pipes for the assignment.

*M.Tsanov, 2022*
