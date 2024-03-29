##### toy debugger in rust via ptrace

- nodep: first libc version to see how things work. stopped working on it after things got too repetitive and i got tired of rewriting nix for no reason and switched to nix
- dbg: using nix, latest version

missing:
- finding main
- attach directly to an active process pid
- instruction translation????
- check bugs and sketchy impls
- move runners inside fork parent and child into their own funcs : brackets too deep
- didnt disable aslr - so what?


usage:

```
app /path
cargo run -- /path
cargo run --bin dbg -- /path

repl cmds:
pmap
si
ins
bp
c
st
mem ?fails bcause stack is empty or something else?
```