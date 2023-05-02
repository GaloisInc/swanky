use std::io::{Cursor, Read};

use mac_n_cheese_sieve_parser::PrintingVisitor;

fn main() -> eyre::Result<()> {
    let mut input = Vec::new();
    std::io::stdin().lock().read_to_end(&mut input)?;
    let parser = mac_n_cheese_sieve_parser::text_parser::RelationReader::new(Cursor::new(input))?;
    println!("{}", parser.header());
    println!("@begin");
    {
        let stdout = std::io::stdout();
        parser.read(&mut PrintingVisitor(stdout.lock()))?;
    }
    println!("@end");
    Ok(())
}
