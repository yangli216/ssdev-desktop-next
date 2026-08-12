use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const HEADER_BYTES: usize = 4;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame length {actual} exceeds limit {limit}")]
    TooLarge { actual: usize, limit: usize },
}

pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize,
{
    let payload = serialize_payload(value)?;
    writer.write_all(&(payload.len() as u32).to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let Some(length) = read_length(reader)? else {
        return Ok(None);
    };
    let payload = read_payload(reader, length)?;
    Ok(Some(serde_json::from_slice(&payload)?))
}

pub async fn write_frame_async<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serialize_payload(value)?;
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame_async<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut header = [0_u8; HEADER_BYTES];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = validate_length(u32::from_le_bytes(header) as usize)?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(serde_json::from_slice(&payload)?))
}

fn serialize_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value)?;
    validate_length(payload.len())?;
    Ok(payload)
}

fn read_length<R: Read>(reader: &mut R) -> Result<Option<usize>, FrameError> {
    let mut first = [0_u8; 1];
    match reader.read(&mut first)? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("single-byte read returned more than one byte"),
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[0] = first[0];
    reader.read_exact(&mut header[1..])?;
    Ok(Some(validate_length(u32::from_le_bytes(header) as usize)?))
}

fn validate_length(length: usize) -> Result<usize, FrameError> {
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            actual: length,
            limit: MAX_FRAME_BYTES,
        });
    }
    Ok(length)
}

fn read_payload<R: Read>(reader: &mut R, length: usize) -> Result<Vec<u8>, FrameError> {
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Message {
        text: String,
    }

    #[test]
    fn sync_round_trip_allows_embedded_newlines() {
        let expected = Message {
            text: "line one\nline two".into(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &expected).unwrap();

        let actual: Message = read_frame(&mut Cursor::new(bytes)).unwrap().unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn clean_eof_is_not_a_protocol_error() {
        let message: Option<Message> = read_frame(&mut Cursor::new(Vec::<u8>::new())).unwrap();
        assert_eq!(message, None);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let length = (MAX_FRAME_BYTES as u32 + 1).to_le_bytes();
        let error = read_frame::<_, Message>(&mut Cursor::new(length)).unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn async_round_trip_matches_sync_wire_format() {
        let expected = Message {
            text: "你好 WebPlus".into(),
        };
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_frame_async(&mut writer, &expected).await.unwrap();

        let actual: Message = read_frame_async(&mut reader).await.unwrap().unwrap();
        assert_eq!(actual, expected);
    }
}
