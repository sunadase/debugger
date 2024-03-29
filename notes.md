Ilk taskin:
X adinda bir syscall var. bu syscall bir process'e attach olmana ve manipule etmene yariyor.
bu syscalli kullanarak coook basit bir debugger yazmalisin.
istenilen adrese breakpoint konulacak ve devam ettirilecek.

strace ptrace ?

sources:
https://dev.to/captainsafia/say-this-five-times-fast-strace-ptrace-dtrace-dtruss-3e1b
https://carstein.github.io/2020/11/18/ptrace-rust.html
https://man7.org/linux/man-pages/man2/ptrace.2.html
https://itnext.io/using-rust-and-ptrace-to-invoke-syscalls-262dc585fcd3
with libc:
https://github.com/codius-deprecated/rust-ptrace/blob/master/src/lib.rs#L177
https://github.com/samwho/rust-debugger/blob/master/src/sys/ptrace/mod.rs

"Under the hood, ***strace*** leverages ***ptrace***, which stands for process trace, a system call that allows a parent process to watch and control the execution of a child process. It's used in ***strace***, but it also enables things like the ***gdb*** debugger."

ptrace
- 2 context switches
- not a posix syscall behavior varies from os to os (there are higher level libraries for unix: nix, rustix)
- must be a child process (security measure -?> how does gdb attach w already running processes work?)
- memory overhead
- alternatives:
    - proccess_vm_read/write: ?
    - 


##### man ptrace / libc ptrace
```c
long ptrace(enum __ptrace_request request, 
            pid_t pid,             
            void* addr, 
            void* data);
```

A process can initiate a trace by calling *fork(2)* and having the resulting child do a PTRACE_TRACEME, followed (typically) by an *execve(2)*. Alternatively, one process may commence tracing another process using PTRACE_ATTACH or PTRACE_SEIZE.

ptrace request enums:
https://github.com/lattera/glibc/blob/master/sysdeps/generic/sys/ptrace.h
https://sites.uclouvain.be/SystInfo/usr/include/sys/ptrace.h.html

nix library use libc calls to libc ptrace functions, to provide a higher level+(platform support:apple+bsds+android+linux:gnu+libc+musl...:archs...@_@) rust api for ptrace


are these the only ways to set a breakpoint?:
 - poke 0xcc(int3) at target addr
 - si till rip reaches target addr: perf overhead

!!!!!
https://man7.org/linux/man-pages/man1/addr2line.1.html
https://github.com/CyberGrandChallenge/binutils/blob/master/binutils/addr2line.c

https://man7.org/linux/man-pages/man3/backtrace.3.html


how to find main
- with and without file analysis?

is the elf/bin analysis only way to find func names

