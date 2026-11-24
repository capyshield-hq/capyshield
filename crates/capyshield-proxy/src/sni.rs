//! Minimal TLS ClientHello parser: just enough to read the SNI without decrypting anything.

#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
    NeedMore,
    NotTls,
    /// A ClientHello; `None` when it carries no server_name (e.g. IP literal).
    Sni(Option<String>),
}

pub fn parse(buf: &[u8]) -> Hello {
    match buf.first() {
        None => return Hello::NeedMore,
        Some(&0x16) => {}
        Some(_) => return Hello::NotTls,
    }
    if buf.len() < 5 {
        return Hello::NeedMore;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + len {
        return Hello::NeedMore;
    }
    let hs = &buf[5..5 + len];
    if hs.first() != Some(&1) {
        return Hello::NotTls;
    }
    // ponytail: a ClientHello split across several records parses as "no SNI"; reassemble if seen in the wild.
    Hello::Sni(server_name(&hs[4..]).flatten())
}

fn server_name(body: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(body);
    r.take(2 + 32)?; // client_version, random
    let n = r.u8()? as usize;
    r.take(n)?; // session_id
    let n = r.u16()? as usize;
    r.take(n)?; // cipher_suites
    let n = r.u8()? as usize;
    r.take(n)?; // compression_methods
    if r.0.is_empty() {
        return Some(None);
    }
    let n = r.u16()? as usize;
    let mut ext = Reader(r.take(n)?);
    while !ext.0.is_empty() {
        let (ty, len) = (ext.u16()?, ext.u16()? as usize);
        let data = ext.take(len)?;
        if ty == 0 {
            let mut d = Reader(data);
            d.u16()?; // list length
            if d.u8()? != 0 {
                return Some(None);
            }
            let n = d.u16()? as usize;
            return Some(String::from_utf8(d.take(n)?.to_vec()).ok());
        }
    }
    Some(None)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}
