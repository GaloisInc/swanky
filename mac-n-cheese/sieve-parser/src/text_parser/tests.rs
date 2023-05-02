use std::io::Cursor;

use crate::PrintingVisitor;

use super::RelationReader;

fn roundtrip(input: &str) -> String {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::mem::drop(color_eyre::install()));
    eprintln!("=====\n{input}\n========");
    use std::fmt::Write;
    let mut out = String::new();
    let parser = RelationReader::new(Cursor::new(input.as_bytes())).unwrap();
    writeln!(out, "{}", parser.header()).unwrap();
    writeln!(out, "@begin").unwrap();
    let mut c = Cursor::new(Vec::new());
    if let Err(e) = parser.read(&mut PrintingVisitor(&mut c)) {
        panic!("{e:?}");
    }
    writeln!(
        out,
        "{}",
        std::str::from_utf8(c.into_inner().as_slice()).unwrap()
    )
    .unwrap();
    writeln!(out, "@end").unwrap();
    out
}

fn test_parse(content: &str, snapshot: &str) {
    let first = roundtrip(content);
    let second = roundtrip(&first);
    assert_eq!(first, second);
    assert_eq!(first.trim(), snapshot.trim());
}

macro_rules! test_case_parses {
    ($name:ident, $content:expr, $snapshot: expr) => {
        #[test]
        fn $name() {
            test_parse($content, $snapshot);
        }
    };
}

test_case_parses!(
    simple,
    "
version 2.0.0; circuit ;
@type field 7; @type field 127;
@begin //thing
@new(\t$1 ... $75654);
@delete(2: $7 ... $96);
@new($/*
Here is an ***important*** block comment
        */75);
@call(thing1);
@call(thing2, $5, $6...$78);
$1 <- @call(thing3);
$75, $8, $9...$45, $674...$800 <- @call(thing4, $1000...$1000);
@end
",
    "
version 2.0.0;
circuit;
@type field 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007;
@type field 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007F;

@begin
@new(0x0:$0x1...$0x12786);
@delete(0x2 : $0x7...$0x60);
@new(0x0:$0x4b...$0x4b);
@call(thing1);
@call(thing2, $0x5,$0x6...$0x4e);
$0x1 <- @call(thing3);
$0x4b,$0x8,$0x9...$0x2d,$0x2a2...$0x320 <- @call(thing4, $0x3e8);

@end"
);

test_case_parses!(
    functions,
    "
version 2.0.0; circuit;
@type field 7; @type field 127; @begin
@function(f1)@end
@function(f2, @out:0x45:4852,4:5,71:2)
    $1 <- $2;
@end
@function(f3, @in:0x45:4852,4:5,71:2)
    $1 <- $2;
@end
@function(f3, @out:85:85, @in:0x45:4852,4:5,71:2)
    $1 <- $2;
@end
@end
",
    "
version 2.0.0;
circuit;
@type field 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007;
@type field 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007F;

@begin
@function(f1)
@end
@function(f2, @out:0x45:0x12f4,0x4:0x5,0x47:0x2)
$0x1 <- 0x0 : $0x2;
@end
@function(f3, @in:0x45:0x12f4,0x4:0x5,0x47:0x2)
$0x1 <- 0x0 : $0x2;
@end
@function(f3, @out:0x55:0x55, @in:0x45:0x12f4,0x4:0x5,0x47:0x2)
$0x1 <- 0x0 : $0x2;
@end

@end
"
);
