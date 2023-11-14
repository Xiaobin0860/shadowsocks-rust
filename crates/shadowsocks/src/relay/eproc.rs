use std::{convert::From, io, vec};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::socks5::Error;

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

///
/// ```plain_auth_data
/// +----+------+----------+------+----------+---------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  | SESSION |
/// +----+------+----------+------+----------+---------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |    8    |
/// +----+------+----------+------+----------+---------+
/// ```
/// ```encrypted_auth_data
/// +----+------+
/// |LEN | DATA |
/// +----+------+
/// | 2  | LEN  |
/// +----+------+
/// ```
pub struct EprocAuthRequest {
    pub uname: Vec<u8>,
    pub passwd: Vec<u8>,
    pub session: u64,
    pub token: u32,
}

impl EprocAuthRequest {
    /// Create a Username/Password Authentication Request
    pub fn new<U, P>(uname: U, passwd: P, session: u64, token: u32) -> Self
    where
        U: Into<Vec<u8>>,
        P: Into<Vec<u8>>,
    {
        let uname = uname.into();
        let passwd = passwd.into();
        assert!(
            !uname.is_empty()
                && uname.len() <= u8::MAX as usize
                && !passwd.is_empty()
                && passwd.len() <= u8::MAX as usize
        );

        Self {
            uname,
            passwd,
            session,
            token,
        }
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let plain_auth_data_len = 1 + 1 + self.uname.len() + 1 + self.passwd.len() + 8;
        let mut plain_auth_data = BytesMut::with_capacity(plain_auth_data_len);
        plain_auth_data.put_u8(0x01);
        plain_auth_data.put_u8(self.uname.len() as u8);
        plain_auth_data.put_slice(&self.uname);
        plain_auth_data.put_u8(self.passwd.len() as u8);
        plain_auth_data.put_slice(&self.passwd);
        plain_auth_data.put_u64(self.session);
        let encrypted_auth_data = eproc_encrypt(&plain_auth_data, self.token);
        let mut buf = BytesMut::with_capacity(2 + encrypted_auth_data.len());
        buf.put_u16_le(encrypted_auth_data.len() as u16);
        buf.put_slice(&encrypted_auth_data);
        w.write_all(&buf).await
    }
}

pub struct EprocAuthResponse {
    pub status: u8,
}

impl EprocAuthResponse {
    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<EprocAuthResponse, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await;

        if buf[0] != 0x01 && buf[0] != 0x05 {
            return Err(Error::UnsupportedEprocAuthVersion(buf[0]));
        }

        Ok(EprocAuthResponse { status: buf[1] })
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        2
    }
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
