/*!
Automate recovery when something goes wrong with the Capcom driver.
 */

// Only available to 64-bit windows targets.
#![cfg(all(windows, target_pointer_width = "64"))]

fn main() {
	match capcom0::recover() {
		Ok(false) => println!("No RECOVER file found. Everything is fine."),
		Ok(true) => println!("Successfully recovered. The RECOVER file was deleted."),
		Err(err) => eprintln!("Failed to recover, user intervention may be required.\n{}", err),
	}
}
