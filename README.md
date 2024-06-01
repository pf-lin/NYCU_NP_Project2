# Network Programming Project 2 - Remote Working Ground (rwg) Server
Design 3 kinds of servers:
1. Design a **Concurrent connection-oriented** server. This server allows one client connect to it.
2. Design a server of the chat-like systems, called remote working systems (rwg). In this system, users can communicate with other users. Use the **single-process concurrent** paradigm to design this server.
3. Design the rwg server using the **concurrent connection-oriented** paradigm with **shared memory** and **FIFO**.

*These three servers must support all functions in Project 1.*

### 3 Servers:
  - np_simple (Single user)
     - `Project 1`
     - **Concurrent connection-oriented**
  - np_single_proc (Multiple users)
     - `Project 1` + `User pipe` + `4 functions` + **Broadcast message**
     - **Single-process concurrent**
  - np_multi_proc (Multiple users)
     - `Project 1` + `User pipe` + `4 functions` + **Broadcast message**
     - **Concurrent connection-oriented** + `FIFO` + **Shared memory**
    - FIFO: User pipe
     - Shared memory: Broadcast message, client information

## Compile
### Build
```
make
```
### Execution
> Usage: [executable file] [port number] 
#### Part 1
```
./np_simple 7000
```
#### Part 2
```
./np_single_proc 7001
```
#### Part 3
```
./np_multi_proc 7002
```
