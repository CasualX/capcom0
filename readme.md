Capcom Zero
===========

Rust bindings to the infamous Capcom driver.

The Capcom driver enables ordinary Administrator applications to gain kernel level ring0 execution privileges.

Binaries
--------

Comes with a binary `elevate` which launches a command prompt with `NT AUTHORITY\SYSTEM` privileges.

Administrator is required to run the binaries. Invoke `build.bat --release` to build the binaries with the right UAC to ask for requireAdministrator when launched.

Examples
--------

Note that Administrator is required to load the Capcom driver.

```rust
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

Details
-------

This section goes in depth to the modifications made to your Windows system and how to manually remove any remaining traces of the Capcom driver and its service.

The library and tools have built in support to write a `RECOVER` file to the current directory. This file contains one or two strings describing the path of the Capcom.sys driver image and the name of its service in the registry. This file is automatically deleted if there were no problems after successfully removing and deleting the driver from your Windows system.

If this file does not exist then there is no problem and everything was cleaned up successfully. Otherwise open the file with a text editor and take note of the information present.

Loading drivers requires them to be registered as a service. Services come in many forms, a [Device Driver](https://en.wikipedia.org/wiki/Device_driver) is a specific kind of service with a payload that is loaded into the Kernel address space. Services are listed in the [Windows Registry](https://en.wikipedia.org/wiki/Windows_Registry) under the tree `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`. The name of the service is the name of its entry under the Services key.

This library creates a new entry for the Capcom service in the Windows Registry. In order to remove the Capcom service, simply find its entry and delete it. To ensure the driver itself is no longer loaded, reboot your computer afterwards.

Find the Capcom service in the Windows Registry using RegEdit simply _CTRL-F_ to open the _Find_ window. If you know the Capcom service name, enter it and look at _Keys_ with _Match whole string only_. If you know the path to the Capcom.sys driver enter it and look at _Data_ without _Match whole string only_. Double check that the find matches the services tree mentioned earlier.

After removing the service try to remove the Capcom.sys driver image. If you are unable (because the file is still in use) it may be the driver is still loaded. A reboot will make sure the driver is no longer loaded and won't be loaded again. Try to delete the Capcom.sys driver image again.

Disclaimer
----------

This driver exposes ring0 kernel resources to arbitrary user programs. There is no authentication to prevent unauthorized access to the capabilities exposed by the Capcom driver.

Anti-virus programs may flag the Capcom driver as a 'hack tool'. This is not a false positive. That is exactly what the Capcom driver is used for. You may choose to whitelist the Capcom driver with your anti-virus program of choice.

Use at your own risk.

Anti-cheat programs do not like the Capcom driver as it can be used to hide cheating behavior. For this reason some companies may ban your user account on sight when their anti-cheat observes a loaded Capcom driver. Simply having the Capcom driver on disk may look suspicious already.

If you play video games, especially those with aggressive anti-cheat programs, I recommend you stay clear of this library.

I disclaim any responsibility for any damage, data loss or other consequences of using this library.

License
-------

Licensed under [MIT License](https://opensource.org/licenses/MIT), see [license.txt](license.txt).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
