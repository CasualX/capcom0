#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::{fmt, mem, ptr};
use obfstr::wide;

pub type PDRIVER_EXTENSION = *mut u8;
pub type PIRP = *mut u8;
pub type PIO_TIMER = *mut u8;
pub type PVPB = *mut u8;
pub type PACCESS_STATE = *mut u8;
pub type ACCESS_MASK = ULONG;
pub type POBJECT_TYPE = *mut u8;
pub type KPROCESSOR_MODE = u8;
pub const KernelMode: u8 = 0;
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;

use winapi::shared::ntdef::{CSHORT, UNICODE_STRING, PUNICODE_STRING, USHORT, ULONG, LONG, PVOID, NTSTATUS};

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
pub type PDRIVER_OBJECT = *mut DRIVER_OBJECT;

#[repr(C)]
pub struct DEVICE_OBJECT {
	pub Type: CSHORT,
	pub Size: USHORT,
	pub ReferenceCount: LONG,
	pub DriverObject: PDRIVER_OBJECT,
	pub NextDevice: PDEVICE_OBJECT,
	pub AttachedDevice: PDEVICE_OBJECT,
	pub CurrentIRP: PIRP,
	pub Timer: PIO_TIMER,
	pub Flags: u32,
	pub Characteristics: u32,
	pub Vpb: PVPB,
	pub DeviceExtension: PVOID,
}
pub type PDEVICE_OBJECT = *mut DEVICE_OBJECT;

struct IAT {
	IoDriverObjectType: *mut POBJECT_TYPE,
	ObReferenceObjectByName: unsafe extern "system" fn(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, *mut PVOID) -> NTSTATUS,
	ObDereferenceObject: unsafe extern "system" fn(PVOID),
	RtlCompareUnicodeString: unsafe extern "system" fn(PUNICODE_STRING, PUNICODE_STRING, u8) -> i32,
	MmIsAddressValid: unsafe extern "system" fn(PVOID) -> u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MOUSE_INPUT_DATA {
	pub UnitId: u16,
	pub Flags: u16,
	pub ButtonFlags: u16,
	pub ButtonData: u16,
	pub RawButtons: u32,
	pub LastX: i32,
	pub LastY: i32,
	pub ExtraInformation: u32,
}
pub type PMOUSE_INPUT_DATA = *mut MOUSE_INPUT_DATA;

fn main() {
	let result = capcom0::setup(|driver, device| {

		let driver_name = driver.file_name();
		println!("DriverName: {}", String::from_utf16_lossy(driver_name));

		unsafe {
			let mut success = false;
			let mut found_handler = FoundHandler::default();

			device.elevate(|ctx| {
				let iat = IAT {
					IoDriverObjectType: ctx.get_system_routine_address(wide!("IoDriverObjectType")),
					ObReferenceObjectByName: ctx.get_system_routine_address(wide!("ObReferenceObjectByName")),
					ObDereferenceObject: ctx.get_system_routine_address(wide!("ObDereferenceObject")),
					RtlCompareUnicodeString: ctx.get_system_routine_address(wide!("RtlCompareUnicodeString")),
					MmIsAddressValid: ctx.get_system_routine_address(wide!("MmIsAddressValid")),
				};

				success = input_handler(&iat, wide!("\\Driver\\mouhid"), wide!("\\Driver\\mouclass"), &mut |found| {
					found_handler = *found;

					let service_callback:
						unsafe extern "system" fn(PDEVICE_OBJECT, PMOUSE_INPUT_DATA, PMOUSE_INPUT_DATA, *mut ULONG) =
						mem::transmute(found.service_callback);

					let mut mouse_input_data = MOUSE_INPUT_DATA {
						UnitId: 0,
						Flags: 0, // MOUSE_MOVE_RELATIVE
						ButtonFlags: 0,
						ButtonData: 0,
						RawButtons: 0,
						LastX: 20,
						LastY: 20,
						ExtraInformation: 0,
					};
					let mouse_input_data_ptr = &mut mouse_input_data as *mut _;
					let mut data_consumed = 0u32;
					service_callback(found.device_object, mouse_input_data_ptr, mouse_input_data_ptr.offset(1), &mut data_consumed);
				});
			});
		println!("success: {:?}\nhandler: {:#?}", success, found_handler);
		}
	});

	match result {
		Ok(()) => println!("Success!"),
		Err(err) => println!("Error: {}", err),
	}
}

#[derive(Copy, Clone, Debug)]
pub struct FoundHandler {
	pub device_object: PDEVICE_OBJECT,
	pub service_callback: usize,
	pub device_object_offset: isize,
	pub service_callback_offset: isize,
}
impl Default for FoundHandler {
	fn default() -> FoundHandler {
		FoundHandler {
			device_object: ptr::null_mut(),
			service_callback: 0,
			device_object_offset: 0,
			service_callback_offset: 0,
		}
	}
}

fn input_handler(iat: &IAT, hid_name: &[u16], class_name: &[u16], f: &mut dyn FnMut(&FoundHandler)) -> bool {
	let mut success = false;

	unsafe {
		let mut hid_name = capcom0::unicode_string(hid_name);
		let mut class_name = capcom0::unicode_string(class_name);
		let mut hid_driver: PDRIVER_OBJECT = ptr::null_mut();
		let mut class_driver: PDRIVER_OBJECT = ptr::null_mut();

		let hid_status = (iat.ObReferenceObjectByName)(&mut hid_name, OBJ_CASE_INSENSITIVE, ptr::null_mut(), 0, *iat.IoDriverObjectType, KernelMode, ptr::null_mut(), &mut hid_driver as *mut _ as *mut PVOID);
		let class_status = (iat.ObReferenceObjectByName)(&mut class_name, OBJ_CASE_INSENSITIVE, ptr::null_mut(), 0, *iat.IoDriverObjectType, KernelMode, ptr::null_mut(), &mut class_driver as *mut _ as *mut PVOID);

		if hid_status >= 0 && !class_driver.is_null() && class_status >= 0 && !class_driver.is_null() {
			let mut device_object = (*hid_driver).DeviceObject;
			while !device_object.is_null() {
				if let Some(found) = search_service(class_driver, device_object, iat) {
					success = true;
					f(&found);
					break;
				}
				device_object = (*device_object).NextDevice;
			}
		}

		if !class_driver.is_null() {
			(iat.ObDereferenceObject)(class_driver as PVOID);
		}
		if !hid_driver.is_null() {
			(iat.ObDereferenceObject)(hid_driver as PVOID);
		}
	}
	success
}
unsafe fn search_service(driver_object: PDRIVER_OBJECT, port_device: PDEVICE_OBJECT, iat: &IAT) -> Option<FoundHandler> {
	let mut temp_device = port_device;
	let mut success = false;
	let driver_start = (*driver_object).DriverStart as usize;
	let driver_end = driver_start + (*driver_object).DriverSize as usize;
	while !(*temp_device).AttachedDevice.is_null() {
		if ((iat.RtlCompareUnicodeString)(&mut (*(*(*temp_device).AttachedDevice).DriverObject).DriverName, &mut (*driver_object).DriverName, 1)) == 0 {
			success = true;
			break;
		}
		temp_device = (*temp_device).AttachedDevice;
	}
	if !success {
		return None;
	}
	let mut target_device_object = (*driver_object).DeviceObject;

	while !target_device_object.is_null() {
		if (*temp_device).AttachedDevice != target_device_object {
			target_device_object = (*target_device_object).NextDevice;
			continue;
		}
		let mut found = FoundHandler::default();
		for i in 0..4096 / 8 {
			let ptr = ((*temp_device).DeviceExtension as *mut usize).offset(i);
			if (iat.MmIsAddressValid)(ptr as PVOID) == 0 {
				break;
			}
			let tmp = *ptr;
			if tmp as PDEVICE_OBJECT == target_device_object {
				found.device_object = target_device_object;
				found.device_object_offset = i;
			}
			if (iat.MmIsAddressValid)(tmp as PVOID) != 0 && tmp > driver_start && tmp < driver_end {
				found.service_callback = tmp;
				found.service_callback_offset = i;
			}
			if !found.device_object.is_null() && found.service_callback != 0 {
				return Some(found);
			}
		}
		target_device_object = (*target_device_object).NextDevice;
	}
	return None;
}
