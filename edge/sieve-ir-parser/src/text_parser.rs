use std::{
    fs::File,
    io::{BufRead, BufReader, Read, Seek},
};

use crypto_bigint::{CheckedAdd, Limb, U64, Uint};
use swanky_error::{ErrorKind, OptionExt, ResultExt, WrapErr};

use crate::{
    ConversionDescription, ConversionSemantics, FunctionBodyVisitor, Header, Number, PluginBinding,
    PluginType, PluginTypeArg, RelationVisitor, Type, TypeId, TypedCount, TypedWireRange,
    ValueStreamKind, WireId, WireRange,
};

#[cold]
#[inline(never)]
fn ascii_str(x: &[u8]) -> impl std::fmt::Debug + '_ {
    String::from_utf8_lossy(x)
}

enum NumberFormat {
    Dec,
    Oct,
    Hex,
    Zero,
}

struct ParseState<T: Read + Seek> {
    inner: BufReader<T>,
}
impl<T: Read + Seek> ParseState<T> {
    #[inline(never)]
    fn skip_comment_after_slash(&mut self) -> swanky_error::Result<()> {
        let mut buf = [0];
        self.inner
            .read_exact(&mut buf)
            .wrap_err(ErrorKind::OtherError, "Failed to read character after '/'")?;
        match buf[0] {
            b'*' => {
                loop {
                    let buf = self
                        .inner
                        .fill_buf()
                        .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?;
                    if buf.is_empty() {
                        // EOF
                        swanky_error::bail!(ErrorKind::OtherError, "Block comment never ended");
                    }
                    if let Some(idx) = memchr::memchr(b'*', buf) {
                        // Consume through the *
                        self.inner.consume(idx + 1);
                        let mut buf = [0];
                        self.inner.read_exact(&mut buf).wrap_err(
                            ErrorKind::OtherError,
                            "Looking for '/' after '*' to terminate block comment",
                        )?;
                        if buf[0] == b'/' {
                            return Ok(());
                        }
                    } else {
                        // Consume the entire buffer
                        let buf_len = buf.len();
                        self.inner.consume(buf_len);
                    }
                }
            }
            b'/' => loop {
                let buf = self
                    .inner
                    .fill_buf()
                    .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?;
                if buf.is_empty() {
                    // EOF
                    return Ok(());
                }
                if let Some(idx) = memchr::memchr(b'\n', buf) {
                    // Consume through the \n
                    self.inner.consume(idx + 1);
                    return Ok(());
                } else {
                    // Consume the entire buffer
                    let buf_len = buf.len();
                    self.inner.consume(buf_len);
                }
            },
            ch => swanky_error::bail!(
                ErrorKind::OtherError,
                "Illegal character to follow '/': {ch:X}"
            ),
        }
    }
    // True means keep reading
    // If f() panics and this function gets called again, it could end up in a broken state. (We
    // abort on panic in the compiler, so it shouldn't be an issue for us.)
    fn read_while(
        &mut self,
        mut f: impl FnMut(u8) -> swanky_error::Result<bool>,
    ) -> swanky_error::Result<()> {
        loop {
            let buf = self
                .inner
                .fill_buf()
                .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?;
            if buf.is_empty() {
                // EOF
                return Ok(());
            }
            for (i, &byte) in buf.iter().enumerate() {
                if !f(byte)? {
                    // DONT consume byte
                    self.inner.consume(i);
                    return Ok(());
                }
            }
            let buf_len = buf.len();
            self.inner.consume(buf_len);
        }
    }
    /// Skip whitespace and comments.
    fn ws(&mut self) -> swanky_error::Result<()> {
        loop {
            // Skip whitespace
            // We'll treat all ASCII control characters as spaces. I don't think there's
            // any good reason for us to double-check that someone didn't sneak a bell
            // character into the source.
            self.read_while(|x| Ok(x <= 32))?;
            match self
                .inner
                .fill_buf()
                .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?
                .first()
                .copied()
            {
                Some(b'/') => {
                    // Currently, if we see a '/', then it must be the beginning of a comment. We
                    // don't see a '/' in any other circumstance.
                    // Consume through the slash.
                    self.inner
                        .read_exact(&mut [0])
                        .wrap_err(ErrorKind::FilesystemError, "Failed to read '/'.")?;
                    self.skip_comment_after_slash()?;
                }
                _ => {
                    return Ok(());
                }
            }
        }
    }

    /// Read a token consisting of
    /// ```regex
    /// [a-zA-Z_][a-zA-Z0-9_]*((.|::)[a-zA-Z_][a-zA-Z0-9_]*)*
    /// ```
    ///
    /// This clears the destination buffer.
    fn token(&mut self, dst: &mut Vec<u8>) -> swanky_error::Result<()> {
        // NOTE: This helper function does not clear dst!
        fn token_part<T: Read + Seek>(
            ps: &mut ParseState<T>,
            dst: &mut Vec<u8>,
        ) -> swanky_error::Result<()> {
            let byte = ps.consume_byte().context("Expected token.")?;
            swanky_error::ensure!(
                ParseState::<T>::is_valid_token_start(byte),
                ErrorKind::OtherError,
                "Invalid token start character {:X}",
                byte
            );
            dst.push(byte);
            ps.read_while(|byte| {
                if ParseState::<T>::is_valid_token_char(byte) {
                    dst.push(byte);
                    Ok(true)
                } else {
                    Ok(false)
                }
            })
        }

        dst.clear();
        self.ws()?;
        token_part(self, dst)?;
        loop {
            match self.peek_n_exact(2)? {
                Some([b'.', _]) => {
                    self.consume_byte()?;
                    dst.push(b'.');
                    token_part(self, dst)?;
                }
                Some([b':', b':']) => {
                    self.consume_byte()?;
                    self.consume_byte()?;
                    dst.push(b':');
                    dst.push(b':');
                    token_part(self, dst)?;
                }
                _ => break,
            }
        }

        Ok(())
    }
    fn expect_byte(&mut self, expected: u8) -> swanky_error::Result<()> {
        self.ws()?;
        let byte = self
            .consume_byte()
            .with_context(|| format!("Expected {:?}. Got EOF", ascii_str(&[expected])))?;
        swanky_error::ensure!(
            byte == expected,
            ErrorKind::OtherError,
            "Got {:?}, but expected {:?}",
            ascii_str(&[byte]),
            ascii_str(&[expected])
        );
        Ok(())
    }
    fn semi(&mut self) -> swanky_error::Result<()> {
        self.expect_byte(b';')
    }
    fn colon(&mut self) -> swanky_error::Result<()> {
        self.expect_byte(b':')
    }
    fn at(&mut self) -> swanky_error::Result<()> {
        self.expect_byte(b'@')
    }
    fn dollar(&mut self) -> swanky_error::Result<()> {
        self.expect_byte(b'$')
    }
    fn dots_real(&mut self) -> swanky_error::Result<()> {
        self.ws()?;
        let mut buf = [0; 3];
        self.inner
            .read_exact(&mut buf)
            .wrap_err(ErrorKind::FilesystemError, "Failed to read dots.")?;
        swanky_error::ensure!(
            buf.as_slice() == b"...",
            ErrorKind::OtherError,
            "Expected '...'. Got {:?}",
            ascii_str(&buf)
        );
        Ok(())
    }
    fn expect_token(&mut self, buf: &mut Vec<u8>, expected: &[u8]) -> swanky_error::Result<()> {
        self.token(buf)?;
        swanky_error::ensure!(
            buf.as_slice() == expected,
            ErrorKind::OtherError,
            "Expected {:?}. Got {:?}.",
            ascii_str(expected),
            ascii_str(buf.as_slice()),
        );
        Ok(())
    }
    fn peek_exact(&mut self) -> swanky_error::Result<Option<u8>> {
        Ok(self
            .inner
            .fill_buf()
            .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?
            .first()
            .copied())
    }
    fn peek_n_exact(&mut self, n: usize) -> swanky_error::Result<Option<&[u8]>> {
        let buf = self
            .inner
            .fill_buf()
            .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?;
        if n > buf.len() {
            return Ok(None);
        }
        Ok(Some(&buf[..n]))
    }
    fn peek(&mut self) -> swanky_error::Result<Option<u8>> {
        self.ws()?;
        self.peek_exact()
    }

    fn peek_n_bytes(&mut self, n: usize) -> swanky_error::Result<&[u8]> {
        self.ws()?;
        Ok(&self
            .inner
            .fill_buf()
            .wrap_err(ErrorKind::FilesystemError, "Failed to fill buffer.")?[..n])
    }

    fn consume_byte(&mut self) -> swanky_error::Result<u8> {
        let mut buf = [0];
        self.inner
            .read_exact(&mut buf)
            .wrap_err(ErrorKind::FilesystemError, "Failed to read byte.")?;
        Ok(buf[0])
    }
    fn number_format(&mut self) -> swanky_error::Result<NumberFormat> {
        match self.peek()? {
            Some(b'0') => {
                self.consume_byte()?;
                match self.peek()? {
                    Some(b'x' | b'X') => {
                        self.consume_byte()?;
                        Ok(NumberFormat::Hex)
                    }
                    Some(b'o' | b'O') => {
                        self.consume_byte()?;
                        Ok(NumberFormat::Oct)
                    }
                    _ => Ok(NumberFormat::Zero),
                }
            }
            _ => Ok(NumberFormat::Dec),
        }
    }
    fn decode_hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(10 + byte - b'a'),
            b'A'..=b'F' => Some(10 + byte - b'A'),
            _ => None,
        }
    }
    fn parse_uint_generic<const LIMBS: usize>(&mut self) -> swanky_error::Result<Uint<LIMBS>> {
        match self.number_format()? {
            NumberFormat::Dec => {
                let mut out = Uint::<LIMBS>::default();
                self.read_while(|byte| {
                    if byte.is_ascii_digit() {
                        out = Option::<_>::from(out.checked_mul(&Uint::<LIMBS>::from_u8(10)))
                            .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
                        out = Option::<_>::from(
                            out.checked_add(&Uint::<LIMBS>::from_u8(byte - b'0')),
                        )
                        .ok_or_swanky_error(ErrorKind::OtherError, "Number too big.")?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })?;
                Ok(out)
            }
            NumberFormat::Oct => todo!("support octal"),
            NumberFormat::Hex => {
                let mut out = Uint::<LIMBS>::default();
                let mut num_nibbles = 0;
                self.read_while(|byte| {
                    if let Some(new_nibble) = Self::decode_hex_nibble(byte) {
                        num_nibbles += 1;
                        if num_nibbles > LIMBS * ((Limb::BITS as usize) / 4) {
                            swanky_error::bail!(ErrorKind::OtherError, "Hex number overflow");
                        }
                        out <<= 4;
                        out |= Uint::<LIMBS>::from_u8(new_nibble);
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })?;
                Ok(out)
            }
            NumberFormat::Zero => Ok(Default::default()),
        }
    }
    fn u8(&mut self) -> swanky_error::Result<u8> {
        let out: U64 = self.parse_uint_generic()?;
        let out: u64 = out.to_words()[0];
        let out = out.try_into().wrap_err(
            ErrorKind::OtherError,
            "Value cannot be represented as a u8.",
        )?;
        Ok(out)
    }
    fn u64(&mut self) -> swanky_error::Result<u64> {
        let out: U64 = self.parse_uint_generic()?;
        Ok(out.to_words()[0])
    }
    fn bignum(&mut self) -> swanky_error::Result<Number> {
        let out: Number = self.parse_uint_generic()?;
        Ok(out)
    }
    fn is_valid_token_start(ch: u8) -> bool {
        matches!(ch, b'a'..=b'z' | b'A'..=b'Z' | b'_')
    }
    fn is_valid_token_char(ch: u8) -> bool {
        Self::is_valid_token_start(ch) | ch.is_ascii_digit()
    }
    fn larrow(&mut self) -> swanky_error::Result<()> {
        self.expect_byte(b'<')?;
        self.expect_byte(b'-')
    }
}

pub struct RelationReader<T: Read + Seek> {
    header: Header,
    ps: ParseState<T>,
}
impl<T: Read + Seek> RelationReader<T> {
    pub fn new(inner: T) -> swanky_error::Result<Self> {
        let ps = ParseState {
            inner: BufReader::with_capacity(1024 * 1024 * 4, inner),
        };
        let mut out = Self {
            header: Header {
                plugins: Vec::new(),
                types: Vec::new(),
                conversion: Vec::new(),
            },
            ps,
        };
        out.parse_header()
            .wrap_err_with(ErrorKind::OtherError, || {
                match out.ps.inner.stream_position() {
                    Ok(pos) => format!("Error occurred at byte position {pos}"),
                    Err(e) => format!("Unable to figure out where error occurred due to {e}"),
                }
            })
            .map(|_| out)
    }
    fn parse_header(&mut self) -> swanky_error::Result<()> {
        let mut buf = Vec::with_capacity(1024);
        self.ps.expect_token(&mut buf, b"version")?;
        self.ps.read_while(|x| Ok(x != b';'))?;
        self.ps.semi()?;
        self.ps.expect_token(&mut buf, b"circuit")?;
        self.ps.semi()?;
        loop {
            self.ps.at()?;
            self.ps.token(&mut buf)?;
            match buf.as_slice() {
                b"plugin" => {
                    self.ps.token(&mut buf)?;
                    self.ps.semi()?;
                    self.header
                        .plugins
                        .push(String::from_utf8_lossy(&buf).to_string());
                }
                b"type" => {
                    match self.ps.peek()? {
                        // Only plugin types use the '@' here
                        Some(b'@') => {
                            self.ps.at()?;
                            self.ps.expect_token(&mut buf, b"plugin")?;
                            self.ps.expect_byte(b'(')?;
                            self.ps.token(&mut buf)?;
                            let name = String::from_utf8_lossy(&buf).to_string();

                            self.ps.expect_byte(b',')?;
                            self.ps.token(&mut buf)?;
                            let operation = String::from_utf8_lossy(&buf).to_string();

                            let mut args = Vec::new();
                            while self.ps.peek()? == Some(b',') {
                                self.ps.expect_byte(b',')?;
                                // Need to determine whether to try to parse a
                                // number or a token - just peek for a digit
                                match self.ps.peek()? {
                                    Some(x) if x.is_ascii_digit() => args
                                        .push(PluginTypeArg::Number(self.ps.parse_uint_generic()?)),
                                    _ => {
                                        self.ps.token(&mut buf)?;
                                        args.push(PluginTypeArg::String(
                                            String::from_utf8_lossy(&buf).to_string(),
                                        ))
                                    }
                                }
                            }

                            self.ps.expect_byte(b')')?;
                            self.ps.semi()?;

                            self.header.types.push(Type::PluginType(PluginType {
                                name,
                                operation,
                                args,
                            }))
                        }
                        _ => {
                            self.ps.token(&mut buf)?;
                            match buf.as_slice() {
                                b"field" => {
                                    let modulus = self.ps.bignum()?;
                                    self.ps.semi()?;
                                    self.header.types.push(Type::Field { modulus });
                                }
                                b"ext_field" => {
                                    let index = self.ps.u8()?;
                                    let degree = self.ps.u64()?;
                                    let modulus = self.ps.u64()?;
                                    self.ps.semi()?;
                                    self.header.types.push(Type::ExtField {
                                        index,
                                        degree,
                                        modulus,
                                    })
                                }
                                b"ring" => {
                                    let nbits = self.ps.u64()?;
                                    self.ps.semi()?;
                                    self.header.types.push(Type::Ring { nbits })
                                }
                                _ => swanky_error::bail!(
                                    ErrorKind::OtherError,
                                    "Unexpected token {:?}",
                                    ascii_str(&buf)
                                ),
                            }
                        }
                    }
                }
                b"convert" => {
                    self.ps.expect_byte(b'(')?;

                    self.ps.at()?;
                    self.ps.expect_byte(b'o')?;
                    self.ps.expect_byte(b'u')?;
                    self.ps.expect_byte(b't')?;

                    self.ps.colon()?;

                    let out_ty = self.ps.u8()?;

                    self.ps.colon()?;

                    let out_count = self.ps.u64()?;

                    self.ps.expect_byte(b',')?;

                    self.ps.at()?;
                    self.ps.expect_byte(b'i')?;
                    self.ps.expect_byte(b'n')?;

                    self.ps.colon()?;

                    let in_ty = self.ps.u8()?;

                    self.ps.colon()?;

                    let in_count = self.ps.u64()?;

                    // TODO: The spec appendix has an extra comma here, but
                    // none of the examples have it, so we don't consume one

                    self.ps.expect_byte(b')')?;
                    self.ps.semi()?;

                    self.header.conversion.push(ConversionDescription {
                        output: TypedCount {
                            ty: out_ty,
                            count: out_count,
                        },
                        input: TypedCount {
                            ty: in_ty,
                            count: in_count,
                        },
                    })
                }
                b"begin" => return Ok(()),
                _ => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Unexpected token {:?}",
                    ascii_str(&buf)
                ),
            }
        }
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Parse `$wire_id` or `type_id : $wire_id`. If the type id isn't provided, it's assumed to be
    /// zero.
    fn read_type_colon_wire_number(&mut self) -> swanky_error::Result<(TypeId, WireId)> {
        let mut type_id = 0;
        if self.ps.peek()? != Some(b'$') {
            // If it doesn't start with a dollar sign, then it's a type colon a wire
            type_id = self.ps.u8().context("Parsing type id before wire")?;
            self.ps.colon()?;
        }
        let wire_id = self.read_wire_id()?;
        Ok((type_id, wire_id))
    }
    fn read_wire_id(&mut self) -> swanky_error::Result<WireId> {
        self.ps.dollar()?;
        self.ps.u64().context("Parsing wire id")
    }
    fn read_new_or_delete_body(&mut self) -> swanky_error::Result<(TypeId, WireId, WireId)> {
        self.ps.expect_byte(b'(')?;
        let (type_id, start) = self.read_type_colon_wire_number()?;
        let end = if self.ps.peek()? == Some(b'.') {
            self.ps.dots_real()?;
            self.read_wire_id()?
        } else {
            start
        };
        self.ps.expect_byte(b')')?;
        self.ps.semi()?;
        Ok((type_id, start, end))
    }
    fn read_wire_range(&mut self) -> swanky_error::Result<WireRange> {
        let start = self.read_wire_id()?;
        let end = if self.ps.peek()? == Some(b'.') {
            self.ps.dots_real()?;
            self.read_wire_id()?
        } else {
            start
        };
        Ok(WireRange { start, end })
    }
    fn check_wire_range_buf_single_output(
        wire_range_buf: &[WireRange],
    ) -> swanky_error::Result<WireRange> {
        swanky_error::ensure!(
            wire_range_buf.len() == 1,
            ErrorKind::OtherError,
            "Expected a single wire range, got {}",
            wire_range_buf.len()
        );
        Ok(wire_range_buf[0])
    }
    fn read_directives<FBV: FunctionBodyVisitor, F>(
        &mut self,
        fbv: &mut FBV,
        mut parse_function: F,
    ) -> swanky_error::Result<()>
    where
        for<'a> F: FnMut(&'a mut Self, &'a mut FBV) -> swanky_error::Result<()>,
    {
        let mut buf = Vec::with_capacity(1024);
        let mut wire_range_buf = Vec::with_capacity(128);
        loop {
            match self.ps.peek()? {
                None => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Unexpected EOF. Expected @end before end of file"
                ),
                Some(b'@') => {
                    self.ps.consume_byte()?;
                    self.ps.token(&mut buf)?;
                    match buf.as_slice() {
                        b"function" => parse_function(self, fbv)?,
                        b"call" => {
                            // call can occur with an assignment if the function returns values
                            self.ps.expect_byte(b'(')?;
                            self.ps.token(&mut buf)?; // the identifier
                            wire_range_buf.clear();
                            while self.ps.peek()? == Some(b',') {
                                self.ps.expect_byte(b',')?;
                                wire_range_buf.push(self.read_wire_range()?);
                            }
                            self.ps.expect_byte(b')')?;
                            self.ps.semi()?;
                            fbv.call(&[], &buf, &wire_range_buf)?;
                        }
                        b"assert_zero" => {
                            self.ps.expect_byte(b'(')?;
                            let (type_id, wire) = self.read_type_colon_wire_number()?;
                            fbv.assert_zero(type_id, wire)?;
                            self.ps.expect_byte(b')')?;
                            self.ps.semi()?;
                        }
                        b"new" => {
                            let (type_id, start, end) = self.read_new_or_delete_body()?;
                            fbv.new(type_id, start, end)?;
                        }
                        b"delete" => {
                            let (type_id, start, end) = self.read_new_or_delete_body()?;
                            fbv.delete(type_id, start, end)?;
                        }
                        b"end" => return Ok(()),
                        _ => swanky_error::bail!(
                            ErrorKind::OtherError,
                            "Saw {:?}. Expected @function, @call, @assert_zero, @new, or @delete",
                            ascii_str(&buf)
                        ),
                    }
                }
                Some(b'$') => {
                    // read the first output wire
                    wire_range_buf.clear();
                    wire_range_buf.push(self.read_wire_range()?);
                    while self.ps.peek()? == Some(b',') {
                        self.ps.expect_byte(b',')?;
                        wire_range_buf.push(self.read_wire_range()?);
                    }
                    self.ps.larrow()?;
                    match self
                        .ps
                        .peek()?
                        .ok_or_swanky_error(ErrorKind::OtherError, "Unexpected EOF after '<-'")?
                    {
                        b'@' => {
                            self.ps.at()?;
                            self.ps.token(&mut buf)?;
                            self.ps.expect_byte(b'(')?;
                            match buf.as_slice() {
                                b"add" => {
                                    let (ty, left) = self.read_type_colon_wire_number()?;
                                    self.ps.expect_byte(b',')?;
                                    let right = self.read_wire_id()?;
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    let dst =
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?
                                            .as_single_wire()?;
                                    fbv.add(ty, dst, left, right)?;
                                }
                                b"mul" => {
                                    let (ty, left) = self.read_type_colon_wire_number()?;
                                    self.ps.expect_byte(b',')?;
                                    let right = self.read_wire_id()?;
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    let dst =
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?
                                            .as_single_wire()?;
                                    fbv.mul(ty, dst, left, right)?;
                                }
                                b"addc" => {
                                    let (ty, left) = self.read_type_colon_wire_number()?;
                                    self.ps.expect_byte(b',')?;
                                    self.ps.expect_byte(b'<')?;
                                    let right = self.ps.bignum()?;
                                    self.ps.expect_byte(b'>')?;
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    let dst =
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?
                                            .as_single_wire()?;
                                    fbv.addc(ty, dst, left, &right)?;
                                }
                                b"mulc" => {
                                    let (ty, left) = self.read_type_colon_wire_number()?;
                                    self.ps.expect_byte(b',')?;
                                    self.ps.expect_byte(b'<')?;
                                    let right = self.ps.bignum()?;
                                    self.ps.expect_byte(b'>')?;
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    let dst =
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?
                                            .as_single_wire()?;
                                    fbv.mulc(ty, dst, left, &right)?;
                                }
                                b"public" => {
                                    let ty = match self.ps.peek()? {
                                        Some(b')') => 0,
                                        _ => self.ps.u8()?,
                                    };
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    fbv.public_input(
                                        ty,
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?,
                                    )?;
                                }
                                b"private" => {
                                    let ty = match self.ps.peek()? {
                                        Some(b')') => 0,
                                        _ => self.ps.u8()?,
                                    };
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    fbv.private_input(
                                        ty,
                                        Self::check_wire_range_buf_single_output(&wire_range_buf)?,
                                    )?;
                                }
                                b"call" => {
                                    let num_outputs = wire_range_buf.len();
                                    self.ps.token(&mut buf)?; // the identifier
                                    while self.ps.peek()? == Some(b',') {
                                        self.ps.expect_byte(b',')?;
                                        wire_range_buf.push(self.read_wire_range()?);
                                    }
                                    self.ps.expect_byte(b')')?;
                                    self.ps.semi()?;
                                    let (outputs, inputs) = wire_range_buf.split_at(num_outputs);
                                    fbv.call(outputs, &buf, inputs)?;
                                }
                                _ => swanky_error::bail!(
                                    ErrorKind::OtherError,
                                    "Unexpected @{:?}",
                                    ascii_str(&buf)
                                ),
                            }
                        }
                        peeked => {
                            // If we don't see an @, then this is either a copy or a constant. Both
                            // start with an optional "type number:", so we don't know which we're
                            // parsing from the beginning.
                            let ty = if peeked != b'<' && peeked != b'$' {
                                // If we see neither a < or $, then assume that it's the type
                                // number up first.
                                let ty = self.ps.u8().context(
                                    "Expecting type number following '<-' for constant or copy",
                                )?;
                                self.ps.colon()?;
                                ty
                            } else {
                                0
                            };
                            let out = Self::check_wire_range_buf_single_output(&wire_range_buf)?;
                            match self.ps.peek()? {
                                Some(b'<') => {
                                    self.ps.expect_byte(b'<')?;
                                    fbv.constant(ty, out.as_single_wire()?, &self.ps.bignum()?)?;
                                    self.ps.expect_byte(b'>')?;
                                }
                                Some(b'$') => {
                                    wire_range_buf.push(self.read_wire_range()?);
                                    while self.ps.peek()? == Some(b',') {
                                        self.ps.expect_byte(b',')?;
                                        wire_range_buf.push(self.read_wire_range()?);
                                    }
                                    let num_input_wires =
                                        wire_range_buf[1..].iter().map(|inp| inp.len()).sum();
                                    swanky_error::ensure!(
                                        out.len() == num_input_wires,
                                        ErrorKind::OtherError,
                                        "Expected {} total input wires, got {}",
                                        out.len(),
                                        num_input_wires
                                    );
                                    fbv.copy(ty, out, &wire_range_buf[1..])?;
                                }
                                ch => swanky_error::bail!(
                                    ErrorKind::OtherError,
                                    "Unexpected {ch:?}. Expected < or $"
                                ),
                            }
                            self.ps.semi()?;
                        }
                    }
                }
                Some(_) => {
                    // It must be a conversion gate
                    let dst_type_id = self
                        .ps
                        .u8()
                        .context("parsing type id of conversion destination")?;
                    self.ps.colon()?;
                    let dst = self.read_wire_range()?;
                    self.ps.larrow()?;
                    self.ps.at()?;
                    self.ps.expect_token(&mut buf, b"convert")?;
                    self.ps.expect_byte(b'(')?;
                    let src_type_id = self.ps.u8()?;
                    self.ps.colon()?;
                    let src = self.read_wire_range()?;
                    let semantics = match self.ps.peek()? {
                        Some(b',') => {
                            self.ps.expect_byte(b',')?;
                            self.ps.at()?;
                            self.ps.token(&mut buf)?;
                            match buf.as_slice() {
                                b"no_modulus" => ConversionSemantics::NoModulus,
                                b"modulus" => ConversionSemantics::Modulus,
                                _ => swanky_error::bail!(
                                    ErrorKind::OtherError,
                                    "Unexpected token {:?}",
                                    ascii_str(&buf)
                                ),
                            }
                        }
                        _ => ConversionSemantics::NoModulus,
                    };
                    self.ps.expect_byte(b')')?;
                    self.ps.semi()?;
                    fbv.convert(
                        TypedWireRange {
                            ty: dst_type_id,
                            range: dst,
                        },
                        TypedWireRange {
                            ty: src_type_id,
                            range: src,
                        },
                        semantics,
                    )?;
                }
            }
        }
    }
    fn read_function(&mut self, rv: &mut impl RelationVisitor) -> swanky_error::Result<()> {
        let mut name = Vec::new();
        let mut outputs = Vec::new();
        let mut inputs = Vec::new();
        self.ps.expect_byte(b'(')?;
        self.ps.token(&mut name)?;
        // We are a bit more permissive than the spec and let people intermix @in and @out if they
        // want to
        let mut dst = &mut outputs;
        loop {
            match self.ps.consume_byte()? {
                b',' => {}
                b')' => break,
                ch => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Expected ',' or ')'. Got {:?}",
                    ascii_str(&[ch])
                ),
            }
            if self.ps.peek()? == Some(b'@') {
                self.ps.consume_byte()?;
                // We can't use token here since token() will keep eat colons.
                self.ps.ws()?;
                match self.ps.consume_byte()? {
                    b'o' => {
                        self.ps.expect_byte(b'u')?;
                        self.ps.expect_byte(b't')?;
                        dst = &mut outputs;
                    }
                    b'i' => {
                        self.ps.expect_byte(b'n')?;
                        dst = &mut inputs;
                    }
                    ch => swanky_error::bail!(
                        ErrorKind::OtherError,
                        "Expected 'o' or 'i'. Got {:?}",
                        ascii_str(&[ch])
                    ),
                }
                self.ps.colon()?;
            }
            // No comma after @out: and @in:
            let ty = self.ps.u8()?;
            self.ps.colon()?;
            let count = self.ps.u64()?;
            dst.push(TypedCount { ty, count });
        }

        // Need to check for "@plugin"
        if self.ps.peek_n_bytes("@plugin".len())? == b"@plugin" {
            let mut buf = Vec::new();
            self.ps.at()?;
            self.ps.expect_token(&mut buf, b"plugin")?;
            self.ps.expect_byte(b'(')?;
            self.ps.token(&mut buf)?;
            let plugin_name = String::from_utf8_lossy(&buf).to_string();

            self.ps.expect_byte(b',')?;
            self.ps.token(&mut buf)?;
            let operation = String::from_utf8_lossy(&buf).to_string();

            // More permissive than the spec: Can intermix arguments and
            // instance/witness declarations
            let mut args = Vec::new();
            let mut private_counts = Vec::new();
            let mut public_counts = Vec::new();
            let mut dst;

            while self.ps.peek()? == Some(b',') {
                self.ps.expect_byte(b',')?;
                match self.ps.peek()? {
                    Some(x) if x.is_ascii_digit() => {
                        args.push(PluginTypeArg::Number(self.ps.parse_uint_generic()?))
                    }
                    Some(b'@') => {
                        self.ps.consume_byte()?;
                        self.ps.ws()?;
                        match self.ps.consume_byte()? {
                            b'p' => match self.ps.consume_byte()? {
                                b'r' => {
                                    self.ps.expect_token(&mut buf, b"ivate")?;
                                    dst = &mut private_counts;
                                }
                                b'u' => {
                                    self.ps.expect_token(&mut buf, b"blic")?;
                                    dst = &mut public_counts;
                                }
                                ch => {
                                    swanky_error::bail!(
                                        ErrorKind::OtherError,
                                        "Expected 'r' or 'u'. Got {:?}",
                                        ascii_str(&[ch])
                                    )
                                }
                            },
                            ch => swanky_error::bail!(
                                ErrorKind::OtherError,
                                "Expected 'p'. Got {:?}",
                                ascii_str(&[ch])
                            ),
                        }
                        self.ps.colon()?;
                        let ty = self.ps.u8()?;
                        self.ps.colon()?;
                        let count = self.ps.u64()?;
                        dst.push(TypedCount { ty, count });
                    }
                    _ => {
                        self.ps.token(&mut buf)?;
                        args.push(PluginTypeArg::String(
                            String::from_utf8_lossy(&buf).to_string(),
                        ))
                    }
                }
            }
            self.ps.expect_byte(b')')?;
            self.ps.semi()?;

            rv.define_plugin_function(
                &name,
                &outputs,
                &inputs,
                PluginBinding {
                    plugin_type: PluginType {
                        name: plugin_name,
                        operation,
                        args,
                    },
                    private_counts,
                    public_counts,
                },
            )?;
        } else {
            rv.define_function(&name, &outputs, &inputs, |fbv| {
                self.read_directives(fbv, |_, _| {
                    swanky_error::bail!(ErrorKind::OtherError, "Nested functions aren't allowed")
                })
            })?;
        }

        Ok(())
    }
    fn read_inner(&mut self, rv: &mut impl RelationVisitor) -> swanky_error::Result<()> {
        self.read_directives(rv, |this, rv| this.read_function(rv))?;
        self.ps.ws()?;
        swanky_error::ensure!(
            (self.ps.peek()?).is_none(),
            ErrorKind::OtherError,
            "Expected EOF after final end"
        );
        Ok(())
    }
    pub fn read(mut self, rv: &mut impl RelationVisitor) -> swanky_error::Result<()> {
        self.read_inner(rv)
            .with_context(|| match self.ps.inner.stream_position() {
                Ok(pos) => format!("Error occurred at byte position {pos}"),
                Err(e) => format!("Unable to figure out where error occurred due to {e}"),
            })
    }
}
impl super::RelationReader for RelationReader<File> {
    fn open(path: &std::path::Path) -> swanky_error::Result<Self> {
        Self::new(
            File::open(path).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Failed to open {path:?}.")
            })?,
        )
    }
    fn read(self, rv: &mut impl RelationVisitor) -> swanky_error::Result<()> {
        <RelationReader<File>>::read(self, rv)
    }
    fn header(&self) -> &Header {
        &self.header
    }
}

pub struct ValueStreamReader<T: Read + Seek> {
    modulus: Number,
    ps: Option<ParseState<T>>,
}
impl<T: Read + Seek> ValueStreamReader<T> {
    pub fn new(kind: ValueStreamKind, t: T) -> swanky_error::Result<Self> {
        let mut ps = ParseState {
            inner: BufReader::with_capacity(1024 * 1024, t),
        };
        let mut buf = Vec::with_capacity(128);
        ps.expect_token(&mut buf, b"version")?;
        ps.read_while(|x| Ok(x != b';'))?;
        ps.semi()?;
        ps.token(&mut buf)?;
        match buf.as_slice() {
            b"public_input" => swanky_error::ensure!(
                kind == ValueStreamKind::Public,
                ErrorKind::OtherError,
                "Got public input file, but expected private"
            ),
            b"private_input" => swanky_error::ensure!(
                kind == ValueStreamKind::Private,
                ErrorKind::OtherError,
                "Got private input file, but expected public"
            ),
            _ => swanky_error::bail!(
                ErrorKind::OtherError,
                "Unexpected file type {:?}",
                ascii_str(&buf)
            ),
        }
        ps.semi()?;
        ps.expect_byte(b'@')?;
        ps.expect_token(&mut buf, b"type")?;
        ps.expect_token(&mut buf, b"field")?;
        let modulus = ps.bignum()?;
        ps.semi()?;
        ps.expect_byte(b'@')?;
        ps.expect_token(&mut buf, b"begin")?;
        Ok(Self {
            modulus,
            ps: Some(ps),
        })
    }
    fn next_inner(&mut self) -> swanky_error::Result<Option<Number>> {
        match self.ps.as_mut() {
            Some(ps) => match ps.peek()? {
                Some(b'@') => {
                    let mut buf = Vec::with_capacity(128);
                    ps.at()?;
                    ps.expect_token(&mut buf, b"end")?;
                    ps.ws()?;
                    swanky_error::ensure!(
                        (ps.peek()?).is_none(),
                        ErrorKind::OtherError,
                        "Expected EOF after final end"
                    );
                    self.ps = None;
                    Ok(None)
                }
                Some(b'<') => {
                    ps.expect_byte(b'<')?;
                    let out = ps.bignum()?;
                    ps.expect_byte(b'>')?;
                    ps.semi()?;
                    Ok(Some(out))
                }
                ch => swanky_error::bail!(ErrorKind::OtherError, "Expected '@' or '<'. Got {ch:?}"),
            },
            _ => Ok(None),
        }
    }
    pub fn modulus(&self) -> &Number {
        &self.modulus
    }
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> swanky_error::Result<Option<Number>> {
        self.next_inner().with_context(|| {
            match self
                .ps
                .as_mut()
                .map(|ps| ps.inner.stream_position())
                .ok_or_swanky_error(ErrorKind::OtherError, "Stream already closed")
            {
                Ok(Ok(pos)) => format!("Error occurred at byte position {pos}"),
                e => format!("Unable to figure out where error occurred due to {e:?}"),
            }
        })
    }
}
impl super::ValueStreamReader for ValueStreamReader<File> {
    fn open(kind: ValueStreamKind, path: &std::path::Path) -> swanky_error::Result<Self> {
        Self::new(
            kind,
            File::open(path).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Failed to open {path:?}.")
            })?,
        )
    }
    fn modulus(&self) -> &Number {
        &self.modulus
    }
    fn next(&mut self) -> swanky_error::Result<Option<Number>> {
        <ValueStreamReader<File>>::next(self)
    }
}

#[cfg(test)]
mod tests;
