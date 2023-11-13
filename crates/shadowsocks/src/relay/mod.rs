//! Relay server in local and server side implementations.

pub use self::socks5::Address;

pub mod socks5;
pub mod tcprelay;
pub mod udprelay;

/// AEAD 2022 maximum padding length
#[cfg(feature = "aead-cipher-2022")]
const AEAD2022_MAX_PADDING_SIZE: usize = 900;

/// Get a properly AEAD 2022 padding size according to payload's length
#[cfg(feature = "aead-cipher-2022")]
fn get_aead_2022_padding_size(payload: &[u8]) -> usize {
    use std::cell::RefCell;

    use rand::{rngs::SmallRng, Rng, SeedableRng};

    thread_local! {
        static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
    }

    if payload.is_empty() {
        PADDING_RNG.with(|rng| rng.borrow_mut().gen::<usize>() % AEAD2022_MAX_PADDING_SIZE)
    } else {
        0
    }
}

fn eproc_encrypt(plain_data: &[u8], token: u32) -> Vec<u8> {
    let plain_data_len = plain_data.len();
    let token = !token;
    let mut padding_len = 0;
    if plain_data_len % 4 != 0 {
        padding_len = 4 - plain_data_len % 4;
    }
    let data_arr_len = plain_data_len + padding_len;
    let mut plain_int_arr = vec![0u32; data_arr_len / 4];
    for i in 0..plain_data_len / 4 {
        let plain_item = &plain_data[i * 4..i * 4 + 4];
        plain_int_arr[i] = u32::from_be_bytes(plain_item.try_into().unwrap());
    }
    if padding_len > 0 {
        let mut last = Vec::from(&plain_data[plain_data_len - plain_data_len % 4..]);
        last.extend(vec![0; padding_len]);
        plain_int_arr[plain_data_len / 4] = u32::from_be_bytes(last.try_into().unwrap());
    }
    plain_int_arr[0] ^= token;
    for i in 0..data_arr_len / 4 - 1 {
        plain_int_arr[i + 1] ^= token;
        plain_int_arr[i + 1] ^= plain_int_arr[i];
    }
    let mut encrypted_data = vec![];
    for encrypt_int in plain_int_arr {
        encrypted_data.extend_from_slice(&encrypt_int.to_be_bytes());
    }
    encrypted_data
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_eproc_encrypt() {
        let hex_str = "010a70726f787974657374650a68656c6c6f31327474320000000000007d54";
        let hex_bytes = hex::decode(hex_str).unwrap();
        let token = 1003052809;
        let encrypted_data = eproc_encrypt(&hex_bytes, token);
        let encrypted_data_str = hex::encode(encrypted_data);
        assert_eq!(
            encrypted_data_str,
            "c53cd0846e720906cf37dd950169180fa93089cb19721b3ddd44bbcb190f4f3d"
        );

        let hex_str = "010970726f7879746573740a68656c6c6f313274743200000000000060e8";
        let hex_bytes = hex::decode(hex_str).unwrap();
        let token = 2830516814;
        let encrypted_data = eproc_encrypt(&hex_bytes, token);
        let encrypted_data_str = hex::encode(encrypted_data);
        assert_eq!(
            encrypted_data_str,
            "5640cdc36e7109065c4bc0bd636711605b1f9ea5786423142f2d9ea5188c2314"
        );

        let hex_str = "010b70726f78797465737465720a68656c6c6f313274743200000000000085f8";
        let hex_bytes = hex::decode(hex_str).unwrap();
        let token = 618923552;
        let encrypted_data = eproc_encrypt(&hex_bytes, token);
        let encrypted_data_str = hex::encode(encrypted_data);
        assert_eq!(
            encrypted_data_str,
            "da1089ad6e730906d01b84bc790a1506ce7d83e827120e05fc09f7da27128bfd"
        );
    }
}
