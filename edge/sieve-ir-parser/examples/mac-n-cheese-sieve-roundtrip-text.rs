use std::io::{Cursor, Read};

use swanky_error::{ErrorKind, WrapErr};
use swanky_sieve_ir_parser::PrintingVisitor;

fn main() -> swanky_error::Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut input)
        .wrap_err(ErrorKind::OtherError, "Failed to read stdin.")?;
    let parser = swanky_sieve_ir_parser::text_parser::RelationReader::new(Cursor::new(input))?;
    println!("{}", parser.header());
    println!("@begin");
    {
        let stdout = std::io::stdout();
        parser.read(&mut PrintingVisitor(stdout.lock()))?;
    }
    println!("@end");
    Ok(())
}
