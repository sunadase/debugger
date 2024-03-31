use clap::builder::Str;
use nix::{libc::user_regs_struct, sys::ptrace, unistd::Pid};
use core::fmt;
use std::{
    borrow::Borrow,
    collections::HashMap,
    error::Error,
    fs,
    io::{self, Write},
    os::raw::c_void,
};
use tracing::{debug, info};

pub fn get_pmap(pid: Pid) -> Result<String, io::Error> {
    let path = format!("/proc/{}/maps", pid);
    return fs::read_to_string(path);
}

pub fn get_mem(pid: Pid) -> Result<String, io::Error> {
    let path = format!("/proc/{}/mem", pid);
    return fs::read_to_string(path);
}

pub fn read_words(pid: Pid, from: usize, size: usize) -> nix::Result<Vec<(usize, usize)>> {
    let mut words = Vec::with_capacity(size);
    let wordlen = std::mem::size_of::<usize>();
    for i in 0..size {
        let addr = from + (wordlen * i);
        words.push((addr, ptrace::read(pid, addr as *mut c_void)? as usize));
    }
    return Ok(words);
}

pub enum Commands {
    PrintMemory(Pid, usize, i32),
    PrintMemoryMap(Pid, usize, i32),
    SingleInstruction(Pid),
    Continue(Pid),
    Breakpoint(Pid, usize),
    State(Pid),
    Instructions(Pid, usize),
}

pub struct REPL {
    /// active target pid
    pub pid: Pid,
    /// if we're expecting a signal in child: must be set
    /// false after non ptrace commands since they dont
    /// induce a signal, repl gets stuck wait()ing a signal
    pub wait: bool,
    ///             bp address, old_instruction
    breakpoints: HashMap<usize, usize>,
}

impl REPL {
    pub fn new(pid: Pid) -> Self {
        REPL {
            pid,
            wait: true,
            breakpoints: HashMap::new(),
        }
    }

    pub fn get_input() -> Result<String, io::Error> {
        let mut input = String::new();
        std::io::stdout().write("> ".as_bytes());
        std::io::stdout().flush();
        std::io::stdin().read_line(&mut input)?;
        Ok(input)
    }

    pub fn parse_input(&mut self, input: &String) -> Result<Commands, String> {
        let args: Vec<String> = input
            .trim()
            .split_whitespace()
            .map(|x| x.to_owned())
            .collect();
        let cmd = match args.first() {
            None => return Err("Error parsing cmd".into()),
            Some(v) => v,
        };
        match cmd.as_str() {
            "mem" | "memory" => {
                if args.len() > 2 {
                    return Err("too many arguments for mem command it expects:\nmem (start) (length), ():optional".into());
                }

                let start = args
                    .get(1)
                    .map(|x| x.parse().unwrap_or_default())
                    .unwrap_or_default();
                let length = args.get(2).map(|x| x.parse().unwrap_or(-1)).unwrap_or(-1);
                self.wait = false;
                return Ok(Commands::PrintMemory(self.pid.to_owned(), start, length));
            }
            "map" | "pmap" => {
                if args.len() > 2 {
                    return Err("too many arguments for pmap command it expects:\nmap (start) (length), ():optional".into());
                }

                let start = args
                    .get(1)
                    .map(|x| x.parse().unwrap_or_default())
                    .unwrap_or_default();
                let length = args.get(2).map(|x| x.parse().unwrap_or(-1)).unwrap_or(-1);
                self.wait = false;
                return Ok(Commands::PrintMemoryMap(self.pid.to_owned(), start, length));
            }
            "si" => {
                self.wait = true;
                return Ok(Commands::SingleInstruction(self.pid.to_owned()));
            }
            "c" | "con" | "cont" => {
                self.wait = true;
                return Ok(Commands::Continue(self.pid.to_owned()));
            }
            "bp" | "b" => {
                if let Some(addr) = args.get(1) {
                    let hex = addr[2..].to_owned();
                    debug!("{} : {}", addr, hex);
                    match usize::from_str_radix(&hex, 16) {
                        Ok(parsed) => {
                            debug!("parsed {} into {:x}", addr, parsed);
                            self.wait = false;
                            return Ok(Commands::Breakpoint(self.pid.to_owned(), parsed));
                        }
                        Err(e) => Err(format!(
                            "Failed parsing {} as a hex string. expected: bp 0x1337",
                            addr
                        )
                        .into()),
                    }
                } else {
                    return Err("Failed parsing addr for breakpoint. expected: bp 0x1337".into());
                }
            }
            "st" | "state" => {
                self.wait = false;
                return Ok(Commands::State(self.pid.to_owned()));
            }
            "ins" | "i" => {
                if args.len() > 1 {
                    return Err(
                        "Got too many args for ins. Expected ins (number): ():optional".into(),
                    );
                }
                let size = args
                    .get(1)
                    .map(|x| x.parse::<usize>().unwrap_or(8))
                    .unwrap_or(8 as usize);
                self.wait = false;
                return Ok(Commands::Instructions(self.pid.to_owned(), size));
            }
            _ => Err(format!("Error parsing input into a command").into()),
        }
    }

    pub fn call_cmds(&mut self, cmd: Commands) -> Result<(), Errors> {
        match cmd {
            Commands::PrintMemory(pid, start, length) => {
                let mem = get_mem(pid)?;
                let lines: Vec<&str> = mem.lines().collect();
                let end;
                if length < 0 {
                    end = lines.len();
                } else {
                    end = start + (length as usize).min(lines.len());
                }
                for line in lines.as_slice()[start..end].iter() {
                    println!("{}", line);
                }
                Ok(())
            }
            Commands::PrintMemoryMap(pid, start, length) => {
                let map = get_pmap(pid)?;
                let lines: Vec<&str> = map.lines().collect();
                let end;
                if length < 0 {
                    end = lines.len();
                } else {
                    end = start + (length as usize).min(lines.len());
                }
                for line in lines.as_slice()[start..end].iter() {
                    println!("{}", line);
                }
                Ok(())
            }
            Commands::Continue(pid) => {
                ptrace::cont(pid, None);
                Ok(())
            }
            Commands::SingleInstruction(pid) => {
                ptrace::step(pid, None);
                Ok(())
            }
            Commands::Breakpoint(pid, addr) => {
                let old_ins = ptrace::read(pid, addr as *mut c_void)? as usize;
                self.breakpoints.insert(addr, old_ins);
                //overwrites on repeat?
                unsafe {
                    ptrace::write(
                        pid,
                        addr as *mut c_void,
                        (old_ins & (usize::MAX - 0xff) | 0xcc) as *mut c_void,
                    );
                }
                Ok(())
            }
            Commands::State(pid) => {
                let rsp = ptrace::getregs(pid)?.rsp;
                let words = read_words(pid, rsp as usize, 16)?;
                for (addr, ins) in words {
                    debug!("@[0x{:x}]> 0x{:x}", addr, ins);
                }
                Ok(())
            }
            Commands::Instructions(pid, size) => {
                let rip = ptrace::getregs(pid)?.rip;
                if let Ok(instructions) = read_words(self.pid, rip as usize, size) {
                    info!("next {} instructions:", size);
                    for (addr, ins) in instructions {
                        info!("@[0x{:x}]> 0x{:x}", addr, ins);
                    }
                }
                Ok(())
            }
        }
    }

    pub fn rep(&mut self) -> Result<(), Errors> {
        return REPL::get_input().map_err(Errors::Io)
            .and_then(|input| self.parse_input(&input).map_err(Errors::Text)
            .and_then(|cmd| self.call_cmds(cmd)));
    }

    pub fn check_breakpoints(&mut self, mut registers: user_regs_struct) {
        debug!("within check bp");
        if self.breakpoints.len() == 0 {
            debug!("nothing to check bps empty");
            return;
        }
        debug!("rip: 0x{:x}", registers.rip);
        // int3 signals just after rip reaches addr?
        // so we are just 1 after bp
        let bp = (registers.rip - 1) as usize;
        debug!(" bp: 0x{:x}", bp);

        // we got the signal and reached the bp so we place the old instruction back
        if let Some(old_ins) = self.breakpoints.remove(bp.borrow()) {
            info!("hit breakpoint: {:x}, replacing old_ins {:x}", bp, old_ins);
            let ins_bp = ptrace::read(self.pid, bp as *mut c_void).unwrap_or(0) as usize;
            let ins_rip =
                ptrace::read(self.pid, registers.rip as *mut c_void).unwrap_or(0) as usize;
            debug!(" bp: @0x{:x} -> 0x{:x}", bp, ins_bp);
            debug!("rip: @0x{:x} -> 0x{:x}", registers.rip, ins_rip);
            if let Ok(instructions) = read_words(self.pid, bp as usize, 9) {
                debug!("next instructions from current bp, rip:");
                let mut name;
                for (addr, ins) in instructions {
                    if addr == (registers.rip as usize) {
                        name = "< rip"
                    } else if addr == bp as usize {
                        name = "< bp"
                    } else {
                        name = ""
                    }
                    debug!("@[0x{:x}]> 0x{:x} {}", addr, ins, name);
                }
            }

            unsafe {
                ptrace::write(self.pid, bp as *mut c_void, old_ins as *mut c_void);
            }

            //post rip state seem to be wrong? rip not inc in prints?
            // bcuz we need to move/update rip 1 back
            registers.rip = bp as u64;
            ptrace::setregs(self.pid, registers.to_owned());

            if let Ok(instructions) = read_words(self.pid, bp as usize, 9) {
                debug!("next instructions from current rip after replacement:");
                let mut name;
                for (addr, ins) in instructions {
                    if addr == (registers.rip as usize) {
                        name = "< rip"
                    } else if addr == bp as usize {
                        name = "< bp"
                    } else {
                        name = ""
                    }
                    debug!("@[0x{:x}]> 0x{:x} {}", addr, ins, name);
                }
            };
        }
        debug!("finished check bp");
    }

    fn get_pmap(pid: Pid) -> io::Result<Vec<u8>> {
        let path = format!("/proc/{}/maps", pid);
        return fs::read(path);
    }

    fn get_mem(pid: Pid) -> io::Result<Vec<u8>> {
        let path = format!("/proc/{}/mem", pid);
        return fs::read(path);
    }

    fn read_words(pid: Pid, from: usize, size: usize) -> nix::Result<Vec<(usize, usize)>> {
        let mut words = Vec::with_capacity(size);
        let wordlen = std::mem::size_of::<usize>();
        for i in 0..size {
            let addr = from + (wordlen * i);
            words.push((
                addr,
                ptrace::read(pid, addr as *mut c_void)?
                    .try_into()
                    .unwrap_or_default(),
            ));
        }
        return Ok(words);
    }
}

pub enum Errors {
    Io(io::Error),
    Text(String),
    Errno(nix::errno::Errno)
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Errors::Errno(ref err) => {write!(f, "Errno: {}", err)},
            Errors::Text(ref err) => {write!(f, "Err: {}", err)},
            Errors::Io(ref err) => {write!(f, "IO error: {}", err)},
        } 
    }
}

impl From<io::Error> for Errors {
    fn from(value: io::Error) -> Self {
        return Errors::Io(value)
    }
}
impl From<String> for Errors {
    fn from(value: String) -> Self {
        return Errors::Text(value)
    }
}

impl From<nix::errno::Errno> for Errors {
    fn from(value: nix::errno::Errno) -> Self {
        return Errors::Errno(value)
    }
}

