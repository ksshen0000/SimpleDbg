# SimpleDbg
From a final project of APUE course.
## compile
g++ sdb.cpp -lcapstone -o sdb
## Launch the program
./sdb PATH_TO_PROGRAM
note that program can only be static-noPIE and only on x86 at current stage.
## commands
`break \<address in hexdecimal\>`: add breakpoint at address.

`cont`: resume from a breakpoint.

`si`: step into next instruction

`anchor `: store the current status of the program.

`timetravel`: restore from the latest anchor.

## Notice
the program will display next 5 instructions after each command executed.
