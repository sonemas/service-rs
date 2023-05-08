use std::error::Error;

fn main() -> Result<(), &'static dyn Error> {
    run()
}

fn run() -> Result<(), &'static dyn Error> {
    println!("Hello, world!");
    Ok(())
}
