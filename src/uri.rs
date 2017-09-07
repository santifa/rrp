#![allow(unused_comparisons)]

use nom::{ErrorKind, IResult};
use nom::{alpha, digit, hex_digit, is_alphanumeric, is_digit, is_hex_digit};
use std::fmt;
use std::str;
/// RRP is a collection of parsers for RDF data written in Rust.
/// Copyright (C) 2017  Henrik Jürges; see the LICENSE file in this repo
///
/// # A module for parsing URI's.
///
///
/// It's main purpose is to validate URI's.
/// A simple URI struct is generated as parsing output.
/// The URI struct is not very sophisticated, but contains the most important
/// parts.
///
/// This implementations shall be close to the
/// (RFC3986 ABNF)[https://tools.ietf.org/html/rfc3986#appendix-A].
///

/// Missing: pct-encoded (something implemented)
#[derive(Debug)]
struct URI<'a> {
    scheme: String,
    domain: Option<Domain<'a>>,
    path: Path<'a>,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl<'a> URI<'a> {
    fn new(s: &str) -> Option<URI> {
        if let IResult::Done(_, uri) = uri_ref(s.as_bytes()) {
            Some(uri)
        } else {
            None
        }
    }

    fn validate(s: &str) -> bool {
        if let IResult::Done(_, _) = uri_ref(s.as_bytes()) {
            true
        } else {
            false
        }
    }
}

impl<'a> fmt::Display for URI<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            {
                if self.scheme == "" { "" } else { &self.scheme }
            },
            {
                if let Some(ref d) = self.domain {
                    d.to_string()
                } else {
                    String::from("")
                }
            },
            self.path.to_string(),
            {
                if let Some(q) = self.query {
                    "?".to_owned() + q
                } else {
                    String::from("")
                }
            },
            {
                if let Some(f) = self.fragment {
                    "#".to_owned() + f
                } else {
                    String::from("")
                }
            }
        )
    }
}

/// The domain holds the user host and port information
#[derive(Debug, PartialEq)]
struct Domain<'a> {
    user: Option<&'a str>,
    host: Host<'a>,
    port: &'a str,
}

impl<'a> fmt::Display for Domain<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            self.user.unwrap_or(""),
            {
                if self.user.is_some() { "@" } else { "" }
            },
            self.host.to_string(),
            {
                if self.port.len() != 0 { ":" } else { "" }
            },
            self.port
        )
    }
}

/// A path is a vector of path segments
#[derive(Debug)]
struct Path<'a>(Vec<&'a str>);

impl<'a> fmt::Display for Path<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0.join("/")) }
}

/// A host can be some IP address or literal or a registered name
#[derive(Debug, PartialEq)]
enum Host<'a> {
    IPv4(&'a str),
    IPvLiteral(&'a str),
    Named(&'a str),
}

impl<'a> Domain<'a> {
    fn new_v4(s: &[u8]) -> Host { Host::IPv4(str::from_utf8(s).unwrap()) }
    fn new_lit(s: &[u8]) -> Host { Host::IPvLiteral(str::from_utf8(s).unwrap()) }
    fn new_named(s: &[u8]) -> Host { Host::Named(str::from_utf8(s).unwrap()) }
    fn get_user_dom(&self) -> String {
        match self.user {
            None => self.host.to_string(),
            Some(u) => u.to_owned() + "@" + &self.host.to_string(),
        }
    }
}

/// The display form is the extraction from the host enum
impl<'a> fmt::Display for Host<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use uri::Host;
        match self {
            &Host::IPv4(a) => write!(f, "{}", a),
            &Host::Named(a) => write!(f, "{}", a),
            &Host::IPvLiteral(a) => write!(f, "[{}]", a),
        }
    }
}


///
/// # Parser for URI's
named!(uri_ref<URI>,
       alt_complete!(uri | relative_ref)
);

named!(relative_ref<URI>,
       do_parse!(
           hier: hier_part >>
               query: opt!(map_res!(query, str::from_utf8)) >>
               frag: opt!(map_res!(fragment, str::from_utf8)) >>
               (URI {
                   scheme: "".to_owned(),
                   domain: hier.0,
                   path: Path(hier.1),
                   query: query,
                   fragment: frag,
               })
       )
);

/// Parse a whole uri, returning a URI struct
named!(uri<URI>,
       do_parse!(
           scheme: scheme >>
               hier: hier_part >>
               query: opt!(map_res!(query, str::from_utf8)) >>
               frag: opt!(map_res!(fragment, str::from_utf8)) >>
               (URI {
                   scheme: scheme.to_owned(),
                   domain: hier.0,
                   path: Path(hier.1),
                   query: query,
                   fragment: frag,
               })
       )
);

/// The strict scheme parsers takes the following characters
/// alpha ( alphanumeric / + / - / . )*
named!(scheme<String>,
       terminated!(
           do_parse!(
               fc: map_res!(alpha, str::from_utf8) >>
                   val: map_res!(take_while!(is_scheme), str::from_utf8) >>
                   (fc.to_owned() + val)
           ),
           tag!(":")
       )
);


/// parses authority path or path only parts
named!(hier_part<(Option<Domain>, Vec<&str>)>,
       alt!(do_parse!(
           tag!("//") >>
               a: authority >>
               p: map!(path_abempty, |i| {
                   let mut v = vec![""];
                   v.append(&mut i.iter().map(|x| str::from_utf8(x).unwrap()).collect());
                   v
               }) >> (Some(a), p)) |
            map!(path_absolute, |v| {
                (None, v.iter().map(|x| str::from_utf8(x).unwrap()).collect() )}) |
            map!(path_rootless, |v| {
                (None, v.iter().map(|x| str::from_utf8(x).unwrap()).collect() )}) |
            map!(path_empty, |v| {
                (None, vec![""])})
       )
);

/// Parse the query part of an URI
named!(query<&[u8]>,
       complete!(do_parse!(
           tag!("?") >>
               q: take_while!(is_query) >>
               (q)))
);

/// Parse the fragment of an URI
named!(fragment<&[u8]>,
       complete!(do_parse!(
           tag!("#") >>
               q: take_while!(is_fragment) >>
               (q)))
);

/// Parse the domain part which consists out of user info, host and port
named!(authority<Domain>,
       do_parse!(
           u: opt!(map_res!(userinfo, str::from_utf8)) >>
           h: host >>
               p: opt!(map_res!(port, str::from_utf8)) >>
               (Domain{
                   user: u,
                   host: h,
                   port: p.unwrap_or("")
               }))
);

/// matches an abitrary string ending with @ and shall not be incomplete
named!(userinfo<&[u8]>,
       complete!(do_parse!(user: take_while!(is_userinfo) >> tag!("@") >> (user)))
);

/// only reg-names allowed at the moment
named!(host<Host>,
       alt_complete!(
           map!(ipv4_address, |i| Domain::new_v4(i)) |
           map!(ip_literal, |i| Domain::new_lit(i)) |
           map!(take_while!(is_basic), |i| Domain::new_named(i)))
);

/// Parse a port number
named!(port<&[u8]>,
       complete!(do_parse!(tag!(":") >> p: take_while!(is_digit) >> (p)))
);

/// match the empty path
named!(path_empty, eof!());

/// matches zero to multiple path segments
named!(path_abempty<Vec<&[u8]>>, many0!(path_part));

/// matches a path without /
named!(path_rootless<Vec<&[u8]>>,
       do_parse!(seg: segment_nz >> seg1: path_abempty >> (concat(vec![seg], seg1)))
);

/// matches a path without / or :
named!(path_noscheme<Vec<&[u8]>>,
       do_parse!(seg: segment_nz_nc >> seg1: path_abempty >> (concat(vec![seg], seg1)))
);

/// matches path segments starting with /
named!(path_absolute<Vec<&[u8]>>,
       do_parse!(
           tag!("/") >>
               seg: opt!(complete!(segment_nz_nc)) >>
               seg1: path_abempty >>
                (concat(vec![&b""[..], seg.unwrap_or(&b""[..])], seg1))
       )
);

/// matches a / and a segment part
named!(path_part<&[u8]>, do_parse!(tag!("/") >> s: segment >> (s)));

/// an empty segment or multiple pchar's
named!(segment<&[u8]>, take_while!(is_pchar));

/// a segment of minimum one pchar
named!(segment_nz<&[u8]>, take_while1!(is_pchar));

/// a segment of minimum one pchar but without colons
named!(segment_nz_nc<&[u8]>, take_while1!(is_pchar_nc));

/// ## IP and Named parsing functions

/// Parse an ipv4 address
named!(ipv4_address<&[u8]>,
       recognize!(do_parse!(
           dec_octed >> tag!(".") >>
               dec_octed >> tag!(".") >>
               dec_octed >> tag!(".") >>
               dec_octed >>
               ()))
);

/// recognize a one to three digits
named!(dec_octed<&[u8]>, recognize!(many_m_n!(1, 3, digit)));

/// Parse an ipv6 or a future address
named!(ip_literal<&[u8]>,
       delimited!(
           tag!("["),
           alt!(ipv6_address | ipv_future),
           tag!("]")
       )
);


/// Parse an ip future address v '..' . '..'
named!(ipv_future<&[u8]>,
       do_parse!(
           tag!("v") >>
               take_while!(is_hex_digit) >>
               tag!(".") >>
               take_while1!(is_future) >>
               ("".as_bytes()))
);


/// ipv6 parsing seems a bit complicated
/// parsing of not fully qualified ipv6 address is not working
named!(ipv6_address<&[u8]>,
       alt_complete!(
           recognize!(call!(ipv6_many, 6)) |
           recognize!(do_parse!(tag!("::") >> call!(ipv6_many, 5) >> ())) |
           recognize!(do_parse!(opt!(h16) >> tag!("::") >> call!(ipv6_many, 4) >> ())) |
           recognize!(do_parse!(
               opt!(call!(ipv6_prefix, 1)) >> tag!("::") >> call!(ipv6_many, 3) >> ()
           )) |
           recognize!(do_parse!(
               opt!(call!(ipv6_prefix, 2)) >> tag!("::") >> call!(ipv6_many, 2) >> ()
           )) |
           recognize!(do_parse!(
               opt!(call!(ipv6_prefix, 3)) >> tag!("::") >> call!(ipv6_many, 1) >> ()
           )) |
           recognize!(do_parse!(
               opt!(call!(ipv6_prefix, 4)) >> tag!("::") >> ls32 >> ()
           )) |
           recognize!(do_parse!(
               opt!(call!(ipv6_prefix, 5)) >> tag!("::") >> h16 >> ()
           )) |
           recognize!(dbg!(do_parse!(
               opt!(call!(ipv6_prefix, 6)) >> tag!("::") >> ()
           ))))
);


/// reading one to four hex digits
named!(h16<&[u8]>, recognize!(many_m_n!(1, 4, hex_digit)));


/// matches hexdigit:
named!(ipv6_part<&[u8]>,
       recognize!(do_parse!(h16 >> tag!(":") >> ()))
);

/// matches hexdigit:hixdigit or an ipv4 address
named!(ls32<&[u8]>,
       alt_complete!(recognize!(tuple!(ipv6_part, h16)) | ipv4_address)
);

/// matches m times an ipv6 part and ls32
named_args!(ipv6_many(num: usize)<&[u8]>,
            recognize!(do_parse!(count!(ipv6_part, num) >> ls32 >> ()))
);

/// matches 0 to n times an ipv6 part and hexdigit
named_args!(ipv6_prefix_max(max: usize)<&[u8]>,
            recognize!(do_parse!(count!(ipv6_part, max) >> h16 >> ()))
);

/// may be a quick shot approach
fn ipv6_prefix(input: &[u8], max: usize) -> IResult<&[u8], &[u8]> {
    let mut counter = max;
    let result;
    loop {
        match ipv6_prefix_max(input, counter) {
            IResult::Done(i, o) => {
                result = IResult::Done(i, o);
                break;
            }
            _ => {
                if counter > 0 {
                    counter -= 1
                } else {
                    result = IResult::Error(ErrorKind::Tag);
                    break;
                }
            }
        }
    }
    result
}


/// Produces a function for char checking
/// ```
/// contains!(name, "str", is_digit) => fn name(c: ..) { c is in "str" ||
/// is_digit ..}
/// ```
macro_rules! contains {
    ($name:ident, $tkn:expr, $($fn:ident),*) => (
        fn $name(chr: u8) -> bool {
            $tkn.chars().any(|t| chr == (t as u8))
                $(|| $fn(chr))*
        }
    );
}

/// helpful functions checking if some char is one of the matching elements
contains!(is_gen_delim, ":/?#[]@",);
contains!(is_sub_delim, "!&'()*+,;=",);
contains!(is_unreserved, "-_.~", is_alphanumeric);
contains!(is_scheme, "-+.", is_alphanumeric);
contains!(is_basic, "", is_unreserved, is_sub_delim, is_pct_encoded);
contains!(is_userinfo, ":", is_basic);
contains!(is_pchar_nc, "@", is_basic);
contains!(is_pchar, ":",is_pchar_nc);
contains!(is_future, ":", is_basic);
contains!(is_query, "/?", is_pchar);
contains!(is_fragment, "/?", is_pchar);
/* not correct testing of pct encoding, since %_a_F is also correct.
 * may be another way of character testing is more appropriate */
contains!(is_pct_encoded, "%", is_hex_digit);

/* concatenate two vectors */
fn concat<'a>(mut s: Vec<&'a [u8]>, s1: Vec<&'a [u8]>) -> Vec<&'a [u8]> {
    s.append(&mut s1.to_vec());
    s
}



#[cfg(test)]
mod test {
    use super::Domain;
    use nom::ErrorKind;
    use nom::IResult;
    use std::str::from_utf8;

    /// (uri, scheme, domain, port, path, query, fragment)
    /// domain includes user and pass
    type TestUri<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, &'a str, &'a str);

    named!(test_part<&str>,
           ws!(delimited!(
               tag!("\""),
               map_res!(take_until!("\""), from_utf8),
               tag!("\""))));

    named!(test_uri<TestUri>,
           tuple!(test_part, test_part, test_part, test_part, test_part, test_part, test_part)
    );

    named!(test_uri_parser<Vec<TestUri>>,
           many0!(ws!(delimited!(tag!("("), test_uri, tag!(")")))));


    //#[test]
    fn test_parser() {
        if let IResult::Done(_, uris) = test_uri_parser(include_bytes!("../assets/uris")) {

            /* test the individual high level parsing parts */
            for uri in uris.iter() {
                if let IResult::Done(rest, uri_s) = super::uri_ref(uri.0.as_bytes()) {
                    assert_eq!(rest, []);
                    assert_eq!(&uri_s.scheme, uri.1);
                    assert_eq!(uri_s.path.to_string(), uri.4);

                    /* test domain */
                    match uri_s.domain {
                        Some(Domain {
                                 user: None,
                                 host: h,
                                 port: p,
                             }) => {
                            assert_eq!(h.to_string(), uri.2);
                            assert_eq!(p, uri.3);
                        }
                        Some(Domain {
                                 user: u,
                                 host: h,
                                 port: p,
                             }) => {
                            let d = u.unwrap().to_owned() + "@" + &h.to_string();
                            assert_eq!(d, uri.2);
                            assert_eq!(p, uri.3);
                        }
                        None => {
                            assert_eq!("", uri.2);
                            assert_eq!("", uri.3);
                        }
                    }

                    match uri_s.query {
                        Some(s) => {
                            assert_eq!(s, uri.5);
                        }
                        None => {
                            assert_eq!("", uri.5);
                        }
                    }
                    match uri_s.query {
                        Some(s) => {
                            assert_eq!(s, uri.6);
                        }
                        None => {
                            assert_eq!("", uri.6);
                        }
                    }
                } else {
                    println!("failed");
                };

            }
        }
    }

    #[test]
    fn test_invalid_schemes() {
        let nuris = vec!["ft/p://ftp.is.co.za/rfc/rfc1808.txt",
                        "ht_tp://www.ietf.org/rfc/rfc2396.txt",
                        "l,dap://[2001:db8::7]/c=GB?objectClass=one"];

        for uri in nuris.into_iter() {
            let r = super::scheme(uri.as_bytes());
            match r {
                IResult::Error(_) => {}
                _ => panic!("Parsing error"),
            }
        }
    }


    /// Test partial parser
    /// first rule: takes a function to test, input, expected output and
    /// optional function args
    /// second rule: takes a fn under test, input, expected output and the
    /// input left
    /// third rule: takes a fn under test, input, error
    macro_rules! btest {
        ($fn:ident, $in:expr, $out:expr $(, $args:expr)*) => ({
            let ok = super::$fn($in.as_bytes() $(, $args)*);
            assert_eq!(ok, IResult::Done(&b""[..], $out));
        });
        ($fn:ident, $in:expr, $out:expr; $left:expr) => ({
            let ok = super::$fn($in.as_bytes());
            assert_eq!(ok, IResult::Done($left, $out));
        });
        ($fn:ident, $in:expr;; $out:expr) => ({
            let err = super::$fn($in.as_bytes());
            assert_eq!(err, IResult::Error($out));
        });
    }

    #[test]
    fn test_fragment() {
        btest!(fragment, "";; ErrorKind::Complete);
        btest!(fragment, "#", &b""[..]);
        btest!(fragment, "#header1", &b"header1"[..]);
    }

    #[test]
    fn test_query() {
        btest!(query, "";; ErrorKind::Complete);
        btest!(query, "?", &b""[..]);
        btest!(query, "?a=1&b=2+2&c=3&c=4&d=%65%6e%63%6F%64%65%64",
                   &b"a=1&b=2+2&c=3&c=4&d=%65%6e%63%6F%64%65%64"[..]);
    }

    #[test]
    fn test_authority() {
        use super::{Domain, Host};
        btest!(authority, "www.ietf.org",
               Domain{user: None, host: Host::Named("www.ietf.org"), port: ""});
        btest!(authority, "alice@example.com",
               Domain{user: Some("alice"), host: Host::Named("example.com"), port: ""});
        btest!(authority, "alice:pass@example.com",
               Domain{user: Some("alice:pass"), host: Host::Named("example.com"), port: ""});
    }

    #[test]
    fn test_port() {
        btest!(port, "";; ErrorKind::Complete);
        btest!(port, ":80", &b"80"[..]);
        btest!(port, ":8000", &b"8000"[..]);
    }

    #[test]
    fn test_host() {
        use super::Host;
        btest!(host, "", Host::Named(""));
        btest!(host, "127.0.0.1", Host::IPv4("127.0.0.1"));
        btest!(host, "example.com", Host::Named("example.com"));
        btest!(host, "[2001:db8::7]", Host::IPvLiteral("2001:db8::7"));
    }

    #[test]
    fn test_user() {
        btest!(userinfo, "";; ErrorKind::Complete);
        btest!(userinfo, "@", &b""[..]);
        btest!(userinfo, "John.Doe@", &b"John.Doe"[..]);
        btest!(userinfo, "alice@", &b"alice"[..]);
        btest!(userinfo, "alice:somepass@", &b"alice:somepass"[..]);
    }

    #[test]
    fn test_dec_octed() {
        btest!(dec_octed, "1", &b"1"[..]);
        btest!(dec_octed, "99", &b"99"[..]);
        btest!(dec_octed, "127", &b"127"[..]);
    }

    #[test]
    fn test_h16() {
        btest!(h16, "0", &b"0"[..]);
        btest!(h16, "1", &b"1"[..]);
        btest!(h16, "2000", &b"2000"[..]);
        btest!(h16, "db8", &b"db8"[..]);
        btest!(h16, "7344", &b"7344"[..]);
        btest!(h16, "0db8", &b"0db8"[..]);
        btest!(h16, "57ab", &b"57ab"[..]);
        btest!(ipv6_part, "2001:", &b"2001:"[..]);
        btest!(ipv6_part, "db8:", &b"db8:"[..]);
    }

    #[test]
    fn test_ipv6_many_prefix() {
        btest!(ipv6_many, "10:127.0.0.1", &b"10:127.0.0.1"[..], 1);
        btest!(ipv6_many, "100:10:127.0.0.1", &b"100:10:127.0.0.1"[..], 2);
        btest!(ipv6_many, "2001:0db8:0", &b"2001:0db8:0"[..], 1);
        btest!(ipv6_many, "2001:0db8:0:0:8d3", &b"2001:0db8:0:0:8d3"[..], 3);
        btest!(ipv6_prefix, "100:10", &b"100:10"[..], 1);
        btest!(ipv6_prefix, "100:10", &b"100:10"[..], 3);
        btest!(ipv6_prefix, "10", &b"10"[..], 0);
    }

    #[test]
    fn test_ip_literal() {
        btest!(ip_literal, "[2001:db8::7]", &b"2001:db8::7"[..]);
    }

    #[test]
    fn test_ipv6() {
        btest!(ipv6_address, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
               &b"2001:0db8:85a3:08d3:1319:8a2e:0370:7344"[..]);
        btest!(ipv6_address, "::ffff:ffff:ffff:ffff:ffff:127.0.0.1",
               &b"::ffff:ffff:ffff:ffff:ffff:127.0.0.1"[..]);
        btest!(ipv6_address, "ffff::ffff:ffff:ffff:ffff:127.0.0.1",
               &b"ffff::ffff:ffff:ffff:ffff:127.0.0.1"[..]);
        btest!(ipv6_address, "::ffff:ffff:ffff:ffff:127.0.0.1",
               &b"::ffff:ffff:ffff:ffff:127.0.0.1"[..]);
        btest!(ipv6_address, "::ffff:ffff:ffff:127.0.0.1",
               &b"::ffff:ffff:ffff:127.0.0.1"[..]);
        btest!(ipv6_address, "ffff:ffff::ffff:ffff:ffff:127.0.0.1",
               &b"ffff:ffff::ffff:ffff:ffff:127.0.0.1"[..]);
        btest!(ipv6_address, "2001:0db8:0:0:8d3::", &b"2001:0db8:0:0:8d3::"[..]);
    }

    #[test]
    fn test_ipv4() {
        btest!(ipv4_address, "127.0.0.1", &b"127.0.0.1"[..]);
    }

    #[test]
    fn test_path_empty() {
        btest!(path_empty, "", &b""[..]);
        btest!(path_empty, "00";; ErrorKind::Eof);
    }

    #[test]
    fn test_path_abempty() {
        btest!(path_abempty, "", vec![]);
        btest!(path_abempty, "/11", vec![&b"11"[..]]);
        btest!(path_abempty, "xx", vec![]; &b"xx"[..]);
    }

    #[test]
    fn test_path_rootless() {
        btest!(path_rootless, "some/", vec![&b"some"[..], &b""[..]]);
        btest!(path_rootless, "some/more/and/more",
               vec![&b"some"[..], &b"more"[..], &b"and"[..], &b"more"[..]]);
        btest!(path_rootless, "/";; ErrorKind::TakeWhile1);
    }

    #[test]
    fn test_path_noscheme() {
        btest!(path_noscheme, "some/", vec![&b"some"[..], &b""[..]]);
        btest!(path_noscheme, "some/more/and/more",
               vec![&b"some"[..], &b"more"[..], &b"and"[..], &b"more"[..]]);
        btest!(path_noscheme, ":";; ErrorKind::TakeWhile1);
    }

    #[test]
    fn test_path_absolute() {
        btest!(path_absolute, "/", vec![&b""[..], &b""[..]]);
        btest!(path_absolute, "/some/", vec![&b""[..], &b"some"[..], &b""[..]]);
        btest!(path_absolute, "/some/more/and/more",
               vec![&b""[..], &b"some"[..], &b"more"[..], &b"and"[..], &b"more"[..]]);
        btest!(path_absolute, ":";; ErrorKind::Tag);
    }
}
