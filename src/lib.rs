extern crate regex;
extern crate rustc_serialize;

use self::regex::Regex;
use self::rustc_serialize::base64::FromBase64;

const REGEX: &'static str = r"(-----BEGIN .*-----\n)((?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\n)+)(-----END .*-----)";

/// Parse the contents of a PEM file and return a DER-serialized byte slice.
/// This won't work if `pem_file_contents` contains more than a single key / certificate.
pub fn pem_to_der(pem_file_contents: &str) -> Vec<u8> {
  let re = Regex::new(REGEX).unwrap();

  let contents_without_headers = re.replace(pem_file_contents, "$2");
  let base64_body = contents_without_headers.replace("\n", "");

  base64_body.from_base64().unwrap()
}
