/*!
This example demonstrates how to simulate input from your real keyboard and mouse.

How it works:

1. Create internal devices for mouse and keyboard
2. DriverObject set MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] to internal handler
3. DeviceObjects set Flags DO_BUFFERED_IO clear Flags DO_DEVICE_INITIALIZING

 */

// Only available to 64-bit windows targets.
#![cfg(all(windows, target_pointer_width = "64"))]

#![allow(non_snake_case, non_camel_case_types)]

use pelite::pattern as pat;
use pelite::pe64::*;
use pelite::pe64::exports::GetProcAddress;

use obfstr::wide;

fn main() {
	// NTOSKRNL image
	let ntoskrnl_map = pelite::FileMap::open(r"C:\Windows\System32\ntoskrnl.exe").unwrap();
	let ntoskrnl_file = PeFile::from_bytes(&ntoskrnl_map).unwrap();


	let result = capcom0::setup(|driver, device| {
		let name = wide!("\\Device\\PointerClass0\0");

		unsafe {
			device.elevate(|ctx| {
				let IoGetDeviceObjectPointer:
					unsafe extern "system" fn(*const u16, u32, *mut PFILE_OBJECT, *mut PDEVICE_OBJECT) -> NTSTATUS =
					ctx.get_system_routine_address(wide!("IoGetDeviceObjectPointer"));
			});
		}
	});

	match result {
		Ok(()) => println!("Success!"),
		Err(err) => println!("Error: {}", err),
	}
}
