use core::fmt;
use std::{
    borrow::Borrow,
    collections::HashMap,
    error::Error,
    fs,
    io::{self, Write},
    os::{
        self,
        raw::c_void,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{exit, Command},
};

use clap::{self, builder::Str, Arg};
use nix::{
    libc::{ptrace, user_regs_struct},
    sys::wait::wait,
    unistd::{getpid, getppid, ForkResult, Pid},
};
use nu_ansi_term::Color;
use tracing::{
    debug, error, field::debug, instrument::WithSubscriber, level_filters::LevelFilter, span,
    Level, Subscriber, Value,
};
use tracing_subscriber::{
    fmt::{format, FormatEvent, FormatFields, FormattedFields},
    registry::LookupSpan,
    EnvFilter,
};

use tracing_core::Event;

use tracing_log::{log::info, NormalizeEvent};

use nix::sys::ptrace;

struct MyFormatter;

impl<S, N> FormatEvent<S, N> for MyFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let normalized_meta = event.normalized_metadata();
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());

        match *meta.level() {
            Level::TRACE => write!(&mut writer, "{}: ", Color::Purple.paint("TRACE")),
            Level::DEBUG => write!(&mut writer, "{}: ", Color::Blue.paint("DEBUG")),
            Level::INFO => write!(&mut writer, "{}: ", Color::Green.paint("INFO")),
            Level::WARN => write!(&mut writer, "{}: ", Color::Yellow.paint("WARN")),
            Level::ERROR => write!(&mut writer, "{}: ", Color::Red.paint("ERROR")),
        }?;

        let current_thread = std::thread::current();
        match current_thread.name() {
            Some(name) => {
                write!(writer, "{} ", FmtThreadName::new(name))?;
            }
            _ => {}
        }
        write!(writer, "{:0>2?} ", current_thread.id())?;

        // Format all the spans in the event's span context.
        if let Some(scope) = ctx.event_scope() {
            write!(writer, "({} > {}) ", getppid(), getpid());
            for span in scope.from_root() {
                write!(writer, "{}", span.name())?;

                // `FormattedFields` is a formatted representation of the span's
                // fields, which is stored in its extensions by the `fmt` layer's
                // `new_span` method. The fields will have been formatted
                // by the same field formatter that's provided to the event
                // formatter in the `FmtContext`.
                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("will never be `None`");

                // Skip formatting the fields if the span had no fields.
                if !fields.is_empty() {
                    write!(writer, "{{{}}}", fields)?;
                }

                write!(writer, ": ")?;
            }
        }

        // Write fields on the event
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

fn main() {
    #[cfg(debug_assertions)]
    let filter_level = LevelFilter::DEBUG;
    #[cfg(not(debug_assertions))]
    let filter_level = LevelFilter::INFO;

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(filter_level.into())
                .from_env_lossy(),
        ) //RUST_LOG
        .event_format(MyFormatter)
        .init();

    span!(Level::DEBUG, "[MAIN]").in_scope(||{

        let cli = clap::Command::new("prog")
        .arg(Arg::new("path_or_pid")
            .index(1)
            .required(true)
            .value_name("PATH/PID")
            .help("Provide a path to an executable to start and attach, or a PID to a running program to attach."));

        let matches = cli.get_matches();
        let path_or_id = matches
            .get_one::<String>("path_or_pid")
            .expect("Expected Path to an executable or a PID");

        debug!("Got path or pid arg: {:?}", path_or_id);

        match parse_arg(path_or_id) {
            Ok(Target::PID(pid)) => {
                todo!()
            }
            // A  process  can  initiate  a  trace by calling fork(2) and
            // having the resulting child do a PTRACE_TRACEME, followed
            // (typically) by an execve(2).
            Ok(Target::Path(path)) => {
                match unsafe {nix::unistd::fork()} {
                    Ok(ForkResult::Child) => {
                        span!(Level::DEBUG, ">[CHILD]").in_scope(||{
                            debug!("Forked, child. pid: {}, ppid: {}", getpid(), getppid());
                            ptrace::traceme();
                            debug!("Ran traceme from child");
                            Command::new(path).exec();
                            debug!("executed the program at child");
                            exit(1);
                        });
                    }
                    Ok(ForkResult::Parent { child }) => {
                        span!(Level::DEBUG, "[PARENT]").in_scope(||{
                            debug!("Forked, parent. pid: {}, ppid: {}", getpid(), getppid());
                            ptrace::attach(child);

                            debug!("attached to child @ {}", child);

                            let mut repl = REPL::new(child);

                            loop {
                                if !&repl.wait{
                                    ptrace::getregs(child).and_then(|regs|{
                                        info!("{:?}", regs);
                                        Ok(())
                                    });

                                    match &repl.rep() {
                                        Err(e) => {
                                            println!("REPL errd with {}", e)
                                        }
                                        _ => {}
                                    }
                                } else {
                                    match nix::sys::wait::wait(){
                                        Ok(wstatus) => {
                                            debug!("{:?}", wstatus);                           
                                            ptrace::getregs(child).and_then(|regs|{
                                                info!("{:?}", regs);
                                                debug!("checking bps..");
                                                repl.check_breakpoints(&regs);
                                                Ok(())
                                            });
                                            

                                            match &repl.rep() {
                                                Err(e) => {
                                                    println!("REPL errd with {}", e);
                                                    repl.wait = false;
                                                }
                                                _ => {}
                                            }

                                        },
                                        Err(e) => {
                                            error!("wait() errored with {}", e);
                                        }
                                    }
                                }
                            }

                        });
                    }
                    Err(e) => {}
                }
            }
            Err(e) => {
                error!("Failed parsing arguments with {:?}", e);
            }
        }
    });
}

fn is_arg_valid_exe(arg: &String) -> Option<&Path> {
    let path = Path::new(arg);
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return None,
    };
    let permissions = metadata.permissions();

    //o stands for octal, file modes are octal since max 777. 111 <==> --x--x--x aka any(executable)
    match metadata.is_file() && (permissions.mode() & 0o111 != 0) {
        true => return Some(path),
        false => return None,
    }
}

fn is_arg_valid_pid(arg: &String) -> Option<u16> {
    return arg.trim().parse().ok();
}

fn parse_arg(arg: &String) -> Result<Target, Box<dyn Error>> {
    match is_arg_valid_pid(arg) {
        Some(pid) => return Ok(Target::PID(pid)),
        None => {}
    }

    match is_arg_valid_exe(arg) {
        Some(path) => return Ok(Target::Path(path.to_owned())),
        None => {}
    }

    return Err(format!("Failed parsing {} as a Path or as a PID", arg).into());
}

enum Target {
    PID(u16),
    Path(PathBuf),
}

struct FmtThreadName<'a> {
    name: &'a str,
}

impl<'a> FmtThreadName<'a> {
    pub(crate) fn new(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> fmt::Display for FmtThreadName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::sync::atomic::{
            AtomicUsize,
            Ordering::{AcqRel, Acquire, Relaxed},
        };

        // Track the longest thread name length we've seen so far in an atomic,
        // so that it can be updated by any thread.
        static MAX_LEN: AtomicUsize = AtomicUsize::new(0);
        let len = self.name.len();
        // Snapshot the current max thread name length.
        let mut max_len = MAX_LEN.load(Relaxed);

        while len > max_len {
            // Try to set a new max length, if it is still the value we took a
            // snapshot of.
            match MAX_LEN.compare_exchange(max_len, len, AcqRel, Acquire) {
                // We successfully set the new max value
                Ok(_) => break,
                // Another thread set a new max value since we last observed
                // it! It's possible that the new length is actually longer than
                // ours, so we'll loop again and check whether our length is
                // still the longest. If not, we'll just use the newer value.
                Err(actual) => max_len = actual,
            }
        }

        // pad thread name using `max_len`
        write!(f, "{:>width$}", self.name, width = max_len)
    }
}

struct REPL {
    /// active target pid
    pid: Pid,
    /// if we're expecting a signal in child: must be set
    /// false after non ptrace commands since they dont
    /// induce a signal, repl gets stuck wait()ing a signal
    wait: bool,
    ///             bp address, old_instruction
    breakpoints: HashMap<usize, usize>,
}

impl REPL {
    fn new(pid: Pid) -> Self {
        REPL {
            pid,
            wait: true,
            breakpoints: HashMap::new(),
        }
    }

    fn get_input() -> Result<String, Box<dyn Error>> {
        let mut input = String::new();
        std::io::stdout().write("> ".as_bytes());
        std::io::stdout().flush();
        std::io::stdin().read_line(&mut input)?;
        Ok(input)
    }

    fn parse_input(&mut self, input: &String) -> Result<Commands, Box<dyn Error>> {
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
                    .map(|x| x.parse().unwrap_or(0).max(0) as usize)
                    .unwrap_or(0);
                //???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
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
                    .map(|x| x.parse().unwrap_or(0).max(0) as usize)
                    .unwrap_or(0);
                //???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                //why does the last unwrap fails without a or/default i thought it was safe??????????????????????????????????????????//
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

    fn call_cmds(&mut self, cmd: Commands) -> Result<(), Box<dyn Error>> {
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

    fn rep(&mut self) -> Result<(), Box<dyn Error>> {
        return REPL::get_input()
            .and_then(|input| self.parse_input(&input).and_then(|cmd| self.call_cmds(cmd)));
    }

    fn check_breakpoints(&mut self, registers: &user_regs_struct) {
        debug!("within check bp");
        if self.breakpoints.len() == 0 {
            debug!("nothing to check bps empty");
            return;
        }
        // int3 signals before rip reaches addr? so we move one step ?further?
        let bp = (registers.rip - 1) as usize;

        // we got the signal and reached the bp so we place the old instruction back
        if let Some(old_ins) = self.breakpoints.remove(bp.borrow()) {
            info!("hit breakpoint: {:x}, replacing old_ins{:?}", bp, old_ins);
            if let Ok(instructions) = read_words(self.pid, registers.rip as usize, 8) {
                debug!("next instructions from current rip:");
                for (addr, ins) in instructions {
                    debug!("@[0x{:x}]> 0x{:x}", addr, ins);
                }
            }

            unsafe {
                ptrace::write(self.pid, bp as *mut c_void, old_ins as *mut c_void);
            }

            //post rip state seem to be wrong? rip not inc in prints?

            if let Ok(instructions) = read_words(self.pid, registers.rip as usize, 8) {
                debug!("next instructions from current rip after replacement:");
                for (addr, ins) in instructions {
                    debug!("@[0x{:x}]> 0x{:x}", addr, ins);
                }
            }
        }

        debug!("finished check bp");
    }
}

enum Commands {
    PrintMemory(Pid, usize, i32),
    PrintMemoryMap(Pid, usize, i32),
    SingleInstruction(Pid),
    Continue(Pid),
    Breakpoint(Pid, usize),
    State(Pid),
    Instructions(Pid, usize),
}

fn get_pmap(pid: Pid) -> Result<String, io::Error> {
    let path = format!("/proc/{}/maps", pid);
    return fs::read_to_string(path);
}

fn get_mem(pid: Pid) -> Result<String, io::Error> {
    let path = format!("/proc/{}/mem", pid);
    return fs::read_to_string(path);
}

fn read_words(pid: Pid, from: usize, size: usize) -> Result<Vec<(usize, usize)>, Box<dyn Error>> {
    let mut words = Vec::with_capacity(size);
    let wordlen = std::mem::size_of::<usize>();
    for i in 0..size {
        let addr = from + (wordlen * i);
        words.push((addr, ptrace::read(pid, addr as *mut c_void)? as usize));
    }
    return Ok(words);
}
