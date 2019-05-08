use std::{fmt, mem, ptr};
use obfstr::wide;

pub type PDEVICE_OBJECT = *mut u8;
pub type PDRIVER_EXTENSION = *mut u8;
pub type PACCESS_STATE = *mut u8;
pub type ACCESS_MASK = ULONG;
pub type POBJECT_TYPE = *mut u8;
pub type KPROCESSOR_MODE = u8;
pub const KernelMode: u8 = 0;
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;

use winapi::shared::ntdef::{CSHORT, UNICODE_STRING, PUNICODE_STRING, ULONG, PVOID, NTSTATUS};

#[repr(C)]
pub struct DRIVER_OBJECT {
	pub Type: CSHORT,
	pub Size: CSHORT,
	pub DeviceObject: PDEVICE_OBJECT,
	pub Flags: ULONG,
	pub DriverStart: PVOID,
	pub DriverSize: ULONG,
	pub DriverSection: PVOID,
	pub DriverExtension: PDRIVER_EXTENSION,
	pub DriverName: UNICODE_STRING,
	//...
}
pub type PDRIVER_OBJECT = *mut DRIVER_OBJECT;

impl fmt::Debug for DRIVER_OBJECT {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("DRIVER_OBJECT")
			.field("Type", &self.Type)
			.field("Size", &self.Size)
			.field("DeviceObject", &self.DeviceObject)
			.field("Flags", &self.Flags)
			.field("DriverStart", &self.DriverStart)
			.field("DriverSize", &self.DriverSize)
			.field("DriverSection", &self.DriverSection)
			.field("DriverExtension", &self.DriverExtension)
			.finish()
	}
}

fn main() {
	let result = capcom0::setup(|driver, device| {

		let driver_name = driver.file_name();
		println!("DriverName: {}", String::from_utf16_lossy(driver_name));

		unsafe {
		let mut mouhid: PDRIVER_OBJECT = ptr::null_mut();
		let mut mouhid_copy: DRIVER_OBJECT = mem::zeroed();
		let mut mouhid_name = capcom0::unicode_string(wide!("\\Driver\\mouclass"));
		let mut mouclass: PDRIVER_OBJECT = ptr::null_mut();
		let mut mouclass_copy: DRIVER_OBJECT = mem::zeroed();
		let mut mouclass_name = capcom0::unicode_string(wide!("\\Driver\\mouclass"));

			device.elevate(|ctx| {
				let IoDriverObjectType:
					*mut POBJECT_TYPE =
					ctx.get_system_routine_address(wide!("IoDriverObjectType"));
				let ObReferenceObjectByName:
					unsafe extern "system" fn(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, *mut PVOID) -> NTSTATUS =
					ctx.get_system_routine_address(wide!("ObReferenceObjectByName"));
				let ObDereferenceObject:
					unsafe extern "system" fn(PVOID) =
					ctx.get_system_routine_address(wide!("ObDereferenceObject"));

				let mouhid_result = ObReferenceObjectByName(&mut mouhid_name, OBJ_CASE_INSENSITIVE, ptr::null_mut(), 0, *IoDriverObjectType, KernelMode, ptr::null_mut(), &mut mouhid as *mut _ as *mut PVOID);
				if !mouhid.is_null() {
					mouhid_copy = ptr::read(mouhid);
					let mouclass_result = ObReferenceObjectByName(&mut mouclass_name, OBJ_CASE_INSENSITIVE, ptr::null_mut(), 0, *IoDriverObjectType, KernelMode, ptr::null_mut(), &mut mouclass as *mut _ as *mut PVOID);
					if !mouclass.is_null() {
						mouclass_copy = ptr::read(mouclass);
						ObDereferenceObject(mouclass as PVOID);
					}
					ObDereferenceObject(mouhid as PVOID);
				}
			});
		println!("mouhid: {:#x}", mouhid as usize);
		println!("mouclass: {:#x}", mouclass as usize);

		println!("mouhid: {:#?}", mouhid_copy);
		println!("mouclass: {:#?}", mouclass_copy);
		}
	});

	match result {
		Ok(()) => println!("Success!"),
		Err(err) => println!("Error: {}", err),
	}
}
