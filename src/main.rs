#![feature(libc)] 
extern crate libc;
use libc::{ptrace};
use std::env;
use std::mem;
use std::process::Command;
use std::process::Child;
use std::ptr;
use std::ffi::CString;

const PTRACE_O_TRACESYSGOOD: i32 = 1;
const ORIG_RAX: i32 = 120;
const RAX: i32 = 80;


fn wait_for_syscall(child: libc::pid_t) -> bool {
	let mut status: i32 = 0;
	let mut exited: bool = true; 
	unsafe {
		
		while true {
			ptrace(libc::PTRACE_SYSCALL, child, 0, 0);
			libc::waitpid(child, status as *mut i32, 0);
			if libc::WIFEXITED(status) {
				exited = true;
				break;
			} 

			if (((status) & 0xff) == 0x7f) && ((((status)  & 0xff00) >> 8) & 0x80) == 1  {
				exited = false;
				break;
			}
		}
	}
	!exited
}

fn make_argv(prog: &CString, args: &[CString]) -> *const *const libc::c_char
{
	let mut ptrs: Vec<*const libc::c_char> = Vec::with_capacity(args.len()+1);

	// Convert the CStrings into an array of pointers. Note: the
	// lifetime of the various CStrings involved is guaranteed to be
	// larger than the lifetime of our invocation of cb, but this is
	// technically unsafe as the callback could leak these pointers
	// out of our scope.
	ptrs.push(prog.as_ptr());
	ptrs.extend(args.iter().map(|tmp| tmp.as_ptr()));

	// Add a terminating null pointer (required by libc).
	ptrs.push(ptr::null());

	ptrs.as_ptr()
}
fn main() {

	
	unsafe {
		let child = libc::fork();
		if child == 0 {
			let cmd = CString::new("whoami").unwrap();
			ptrace(libc::PTRACE_TRACEME);
			
			libc::kill(libc::getpid(), libc::SIGSTOP);
			let args = make_argv(&cmd, &[]);
			libc::execvp(*args, args);

		} else {

			let (mut syscall, mut retval): (i64, i64);

			libc::waitpid(child, 0 as *mut i32, 0);
			ptrace(libc::PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

			while true {
				if wait_for_syscall(child) {
					break
				}

				unsafe {
					syscall = ptrace(libc::PTRACE_PEEKUSER, child, 32*ORIG_RAX);
					println!("syscall: {:?}", syscall );
				} 

				if wait_for_syscall(child) {
					break
				}

				unsafe {
					retval = ptrace(libc::PTRACE_PEEKUSER, child, 32*RAX);
					println!("retval: {:?}", retval );
				}
			}
		}
	}

}
