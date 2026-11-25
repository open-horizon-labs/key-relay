//! The paired key's getInfo fields and the receiver's getInfo template
//! (docs/relay-contract.md, "getInfo template").

use ciborium::value::{Integer, Value};
use serde::Deserialize;

/// Cached at pairing from the YubiKey's own getInfo.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyInfo {
    /// 32 hex digits, with or without dashes.
    pub aaguid: String,
    pub max_msg_size: u32,
    pub max_credential_count_in_list: Option<u32>,
    pub max_credential_id_length: Option<u32>,
    /// COSE algorithm identifiers, e.g. [-7, -8].
    pub algorithms: Vec<i64>,
    /// PIN/UV auth protocol versions, e.g. [2, 1]. Clients need at least one even
    /// for built-in UV: they send getUVRetries with a protocol version
    /// (python-fido2 2.2.1 refuses to proceed without one).
    #[serde(default = "default_pin_uv_auth_protocols")]
    pub pin_uv_auth_protocols: Vec<u64>,
}

fn default_pin_uv_auth_protocols() -> Vec<u64> {
    vec![2, 1]
}

impl KeyInfo {
    pub fn aaguid_bytes(&self) -> Result<[u8; 16], String> {
        let hex: String = self.aaguid.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(format!("aaguid must have 32 hex digits, got {}", hex.len()));
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }

    /// The getInfo response body (without the status byte), canonical CTAP2 CBOR.
    pub fn get_info_cbor(&self) -> Result<Vec<u8>, String> {
        let int = |n: i64| Value::Integer(Integer::from(n));
        let text = |s: &str| Value::Text(s.to_string());
        // Entries are listed in canonical order: integer keys ascending, then text keys
        // by encoded length and bytewise ("rk" < "up" < "uv" < "plat"; "alg" < "type").
        let mut map = vec![
            (int(0x01), Value::Array(vec![text("FIDO_2_0")])),
            (int(0x03), Value::Bytes(self.aaguid_bytes()?.to_vec())),
            (
                int(0x04),
                Value::Map(vec![
                    (text("rk"), Value::Bool(true)),
                    (text("up"), Value::Bool(true)),
                    (text("uv"), Value::Bool(true)),
                    (text("plat"), Value::Bool(false)),
                ]),
            ),
            (int(0x05), int(self.max_msg_size.into())),
            (int(0x06), Value::Array(self.pin_uv_auth_protocols.iter().map(|v| int(*v as i64)).collect())),
        ];
        if let Some(n) = self.max_credential_count_in_list {
            map.push((int(0x07), int(n.into())));
        }
        if let Some(n) = self.max_credential_id_length {
            map.push((int(0x08), int(n.into())));
        }
        map.push((int(0x09), Value::Array(vec![text("usb")])));
        map.push((
            int(0x0A),
            Value::Array(
                self.algorithms
                    .iter()
                    .map(|alg| Value::Map(vec![(text("alg"), int(*alg)), (text("type"), text("public-key"))]))
                    .collect(),
            ),
        ));
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }
}

#[cfg(test)]
pub fn test_key_info() -> KeyInfo {
    KeyInfo {
        aaguid: "00000000-0000-0000-0000-000000000000".into(),
        max_msg_size: 1200,
        max_credential_count_in_list: Some(8),
        max_credential_id_length: Some(128),
        algorithms: vec![-7, -8],
        pin_uv_auth_protocols: vec![2, 1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_advertises_built_in_uv_and_no_client_pin() {
        let bytes = test_key_info().get_info_cbor().unwrap();
        let value: Value = ciborium::from_reader(&bytes[..]).unwrap();
        let Value::Map(entries) = value else { panic!() };
        let get = |k: i64| entries.iter().find(|(key, _)| *key == Value::Integer(k.into())).map(|(_, v)| v.clone());
        assert_eq!(get(1), Some(Value::Array(vec![Value::Text("FIDO_2_0".into())])));
        let Some(Value::Map(options)) = get(4) else { panic!() };
        let names: Vec<_> = options.iter().map(|(k, _)| k.as_text().unwrap().to_string()).collect();
        assert_eq!(names, ["rk", "up", "uv", "plat"]);
        assert!(!names.contains(&"clientPin".to_string()));
        assert_eq!(get(7), Some(Value::Integer(8.into())));
        assert_eq!(get(2), None, "no extensions advertised");
        assert_eq!(get(6), Some(Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())])));
    }

    #[test]
    fn get_info_bytes_are_canonical() {
        // Keys 1,3,4,5,6,7,8,9,10 ascending; options in canonical text order.
        let bytes = test_key_info().get_info_cbor().unwrap();
        assert_eq!(bytes[0], 0xA9, "map of 9 entries");
        assert_eq!(&bytes[1..3], &[0x01, 0x81]);
        let options = [0xA4, 0x62, b'r', b'k', 0xF5, 0x62, b'u', b'p', 0xF5, 0x62, b'u', b'v', 0xF5, 0x64, b'p', b'l', b'a', b't', 0xF4];
        assert!(bytes.windows(options.len()).any(|w| w == options));
    }

    #[test]
    fn rejects_bad_aaguid() {
        let mut info = test_key_info();
        info.aaguid = "abc".into();
        assert!(info.get_info_cbor().is_err());
    }
}
