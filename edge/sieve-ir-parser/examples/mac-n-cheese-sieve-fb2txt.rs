use std::path::Path;

use swanky_sieve_ir_parser::{PrintingVisitor, RelationReader, fb_reader};

fn main() -> swanky_error::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let parser = fb_reader::RelationReader::open(Path::new(args[1].as_str()))?;
    println!("{}", parser.header());
    println!("@begin");
    {
        let stdout = std::io::stdout();
        parser.read(&mut PrintingVisitor(stdout.lock()))?;
    }
    println!("@end");
    Ok(())
}
