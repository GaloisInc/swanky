use std::path::Path;

use mac_n_cheese_sieve_parser::{fb_reader, PrintingVisitor, RelationReader};

fn main() -> eyre::Result<()> {
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
