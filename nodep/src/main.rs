use core::fmt;
use std::{
    error::Error,
    io,
    os::{
        self,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

use clap::{self, builder::Str, Arg};
use libc::{self, exit, pid_t, write};
use nu_ansi_term::Color;
use tracing::{
    debug, error, field::debug, instrument::WithSubscriber, level_filters::LevelFilter, span,
    Level, Subscriber, Value,
};
use tracing_subscriber::{
    fmt::{FormatEvent, FormatFields, FormattedFields},
    registry::LookupSpan,
    EnvFilter,
};

use tracing_core::Event;

use tracing_log::NormalizeEvent;

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
            write!(writer, "({} > {}) ", getparentpid(), getpid());
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
                match fork() {
                    Ok(ForkResult::Child) => {
                        span!(Level::DEBUG, ">[CHILD]").in_scope(||{
                            debug!("Forked, child. pid: {}, ppid: {}", getpid(), getparentpid());
                            PTracer::traceme().expect("Failed traceme somehow??");
                            debug!("Ran traceme from child");
                            Command::new(path).exec();
                            debug!("executed the program at child");
                            unsafe { exit(0) };
                        });
                    }
                    Ok(ForkResult::Parent { child }) => {
                        span!(Level::DEBUG, "[PARENT]").in_scope(||{
                            debug!("Forked, parent. pid: {}, ppid: {}", getpid(), getparentpid());

                            PTracer::attach(child.into());

                            debug!("attached to child @ {}", child);

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

struct PTracer {
    target: Target,
}

impl PTracer {
    fn call(
        request: Requests,
        pid: libc::pid_t,
        addr: *mut libc::c_void,
        data: *mut libc::c_void,
    ) -> Result<libc::c_long, Box<dyn Error>> {
        let value;
        unsafe {
            value = libc::ptrace(request as libc::c_uint, pid, addr, data);
        }
        match value {
            // On  error,  all  requests  return  -1,  and  errno  is set appropriately.  Since the value
            // returned by a successful PTRACE_PEEK* request may be  -1,  the  caller  must  clear  errno
            // before  the  call,  and  then  check  it  afterward  to  determine whether or not an error
            // occurred.
            -1 => Err(io::Error::last_os_error().into()),

            // On  success,  the  PTRACE_PEEK*  requests  return  the requested data (but see NOTES), the
            // PTRACE_SECCOMP_GET_FILTER request returns the number of instructions in the  BPF  program,
            // and other requests return zero.
            _ => Ok(value),
        }
    }

    fn traceme() -> Result<(), Box<dyn Error>> {
        //ptrace(traceme, 0, 0, 0)
        PTracer::call(
            Requests::TraceMe,
            Pid::from_raw(0).into(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .map(drop)
    }

    fn attach(pid: Pid) -> Result<(), Box<dyn Error>> {
        PTracer::call(
            Requests::Attach,
            pid.into(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .map(drop)
    }

    fn detatch(pid: Pid) -> Result<(), Box<dyn Error>> {
        PTracer::call(
            Requests::Detach,
            pid.into(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .map(drop)
    }
    /// If pid is positive, then signal sig is sent to the process with
    /// the ID specified by pid.
    ///
    /// If pid equals 0, then sig is sent to every process in the process
    ///  group of the calling process.
    ///
    /// If pid equals -1, then sig is sent to every process for which the
    ///  calling process has permission to send signals, except for
    ///  process 1 (init), but see below.
    ///
    /// If pid is less than -1, then sig is sent to every process in the
    ///  process group whose ID is -pid.
    ///
    /// If sig is 0, then no signal is sent, but existence and permission
    ///  checks are still performed; this can be used to check for the
    ///  existence of a process ID or process group ID that the caller is
    ///  permitted to signal.
    fn kill(pid: Pid, sig: i32) -> Result<(), Box<dyn Error>> {
        let result = unsafe { libc::kill(pid.into(), sig.into()) };
        match result {
            0 => Ok(()),
            _ => {
                let err = io::Error::last_os_error();
                return Err(format!("libc::kill errored with errno: {}", err).into());
            }
        }
    }
}

enum Requests {
    TraceMe = libc::PTRACE_TRACEME as isize,
    PeekText = libc::PTRACE_PEEKTEXT as isize,
    PeekData = libc::PTRACE_PEEKDATA as isize,
    PeekUser = libc::PTRACE_PEEKUSER as isize,
    PokeText = libc::PTRACE_POKETEXT as isize,
    PokeData = libc::PTRACE_POKEDATA as isize,
    PokeUser = libc::PTRACE_POKEUSER as isize,
    Cont = libc::PTRACE_CONT as isize,
    Kill = libc::PTRACE_KILL as isize,
    Singlestep = libc::PTRACE_SINGLESTEP as isize,
    Attach = libc::PTRACE_ATTACH as isize,
    Syscall = libc::PTRACE_SYSCALL as isize,
    SetOptions = libc::PTRACE_SETOPTIONS as isize,
    GetEventMsg = libc::PTRACE_GETEVENTMSG as isize,
    GetSigInfo = libc::PTRACE_GETSIGINFO as isize,
    SetSigInfo = libc::PTRACE_SETSIGINFO as isize,
    GetRegSet = libc::PTRACE_GETREGSET as isize,
    SetRegSet = libc::PTRACE_SETREGSET as isize,
    Seize = libc::PTRACE_SEIZE as isize,
    Interrupt = libc::PTRACE_INTERRUPT as isize,
    Listen = libc::PTRACE_LISTEN as isize,
    PeekSigInfo = libc::PTRACE_PEEKSIGINFO as isize,
    GetSigMask = libc::PTRACE_GETSIGMASK as isize,
    SetSigMask = libc::PTRACE_SETSIGMASK as isize,
    GetSyscallInfo = libc::PTRACE_GET_SYSCALL_INFO as isize,
    Detach = libc::PTRACE_DETACH as isize,
}

// SyscallInfoNone = libc::PTRACE_SYSCALL_INFO_NONE as isize,
// SyscallInfoEntry = libc::PTRACE_SYSCALL_INFO_ENTRY as isize,
// SyscallInfoExit = libc::PTRACE_SYSCALL_INFO_EXIT as isize,
// SyscallInfoSecComp = libc::PTRACE_SYSCALL_INFO_SECCOMP as isize,

enum ForkResult {
    Child,
    Parent { child: Pid },
}

fn getpid() -> Pid {
    Pid(unsafe { libc::getpid() })
}

fn getparentpid() -> Pid {
    Pid(unsafe { libc::getppid() })
}

//im basically rewriting parts of nix crate at this point but...
//ill at least cont with nodep till i hvae smth
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Pid(pid_t);

impl Pid {
    const fn from_raw(pid: pid_t) -> Self {
        Pid(pid)
    }

    fn this() -> Self {
        getpid()
    }

    fn parent() -> Self {
        getparentpid()
    }

    const fn as_raw(self) -> pid_t {
        self.0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f) //?
    }
}

impl From<Pid> for pid_t {
    fn from(pid: Pid) -> Self {
        return pid.0;
    }
}

fn fork() -> Result<ForkResult, Box<dyn Error>> {
    // On success, the PID of the child process is returned in the parent,
    // and 0 is  returned  in the  child. On  failure, -1 is returned in
    // the parent, no child process is created, and errno is set appropriately.
    let fork_res = unsafe { libc::fork() };

    match fork_res {
        -1 => {
            //error
            return Err(format!("Fork failed with errno {:?}", io::Error::last_os_error()).into());
        }
        0 => return Ok(ForkResult::Child),
        x => return Ok(ForkResult::Parent { child: Pid(x) }),
    }
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
