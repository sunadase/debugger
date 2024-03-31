use clap::{self, Arg};
use nix::sys::ptrace;
use nix::unistd::{getpid, getppid, ForkResult, Pid};
use std::{
    error::Error,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{exit, Command},
};
use tracing::{debug, error, level_filters::LevelFilter, span, Level};
use tracing_log::log::info;
use tracing_subscriber::EnvFilter;

mod repl;
mod tracing_formatter;
use repl::REPL;
use tracing_formatter::MyFormatter;

fn child_runner(path: &PathBuf) {
    debug!("Forked, child. pid: {}, ppid: {}", getpid(), getppid());
    ptrace::traceme();
    debug!("Ran traceme from child");
    Command::new(path).exec();
    debug!("executed the program at child");
    exit(1);
}

fn parent_runner(repl: &mut REPL, child: Pid) {
    loop {
        if !&repl.wait {
            ptrace::getregs(child).and_then(|regs| {
                info!("{:x?}", regs);
                Ok(())
            });

            match &repl.rep() {
                Err(e) => {
                    error!("REPL errd with {}", e)
                }
                _ => {}
            }
        } else {
            match nix::sys::wait::wait() {
                Ok(wstatus) => {
                    debug!("{:?}", wstatus);
                    ptrace::getregs(child).and_then(|regs| {
                        info!("{:x?}", regs);
                        debug!("checking bps..");
                        repl.check_breakpoints(regs);
                        Ok(())
                    });

                    match &repl.rep() {
                        Err(e) => {
                            error!("REPL errd with {}", e);
                            repl.wait = false;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("wait() errored with {}", e);
                }
            }
        }
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
                            child_runner(&path);
                        });
                    }
                    Ok(ForkResult::Parent { child }) => {
                        span!(Level::DEBUG, "[PARENT]").in_scope(||{
                            debug!("Forked, parent. pid: {}, ppid: {}", getpid(), getppid());
                            ptrace::attach(child);
                            debug!("attached to child @ {}", child);

                            let mut repl = REPL::new(child);

                            parent_runner(&mut repl, child);
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
