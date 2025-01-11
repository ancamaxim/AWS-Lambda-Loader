## 323CC Rusanescu Andrei-Marian, 324CC Maxim Anca-Stefania

## [Github Link](https://github.com/andreirusanescu/lambda-loader)

This project enables users to execute functions from a specified dynamic library,
by leveraging client-server communication.

## Signal and Process handling
The implementation handles the client-server communication
through the usage of a separate process for every accepted
connection and an additional process for every function
execution for better memory management and security, while
achieving an overall great performance. This choice is motivated
by greater separation between resources, in the event of an exit
call in the executed function caused by an interrupt or a segmentation
fault.

Moreover, signal handling is done through the usage of sigaction(), which enables
us to create custom signal handler functions for the following signals: `SIGSEGV`
and `SIGINT`. 

## Command Line Arguments
The project provides additional support for network socket communication, through
the usage of `--inet` argument. Using `--client_count=x`, where `x` is a number,
the user sets the max number of clients for the server. If the client count is not specified,
the default value is 100. For more information about the usage, run the
server using the command `LD_LIBRARY_PATH=./../src/. ../src/server --help`
from the tests folder after compiling the sources using `make clean && make`
in src folder.

## Unix and Inet sockets
Firstly the command-line arguments are checked for custom
options of the server. Then, the sockets type is chosen 
(`Unix` or `Inet`). The server can have both remote and local 
connections.

We implemented an internet client that uses inet sockets to
connect to the server called `client_inet.c`. To compile it,
run make in the src folder. When the server gets a connection through
internet, its ip address and port are printed in the log file.


## Logging
Logging was managed through the usage of log.c and log.h files.
Created specialised functions for output logging in 
`server.log` file. Using `create_log()` the logging is initialised.
Using `dlog()` with the `message` to be shown and format (`INFO`,
`DEBUG`, `WARNING`), displayed in the enum `log_t`.

