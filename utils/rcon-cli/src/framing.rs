use std::io::ErrorKind;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_json_message<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];

    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        bail!("received empty frame");
    }

    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read JSON payload")?;

    let message = serde_json::from_slice(&payload).context("failed to decode JSON frame")?;
    Ok(Some(message))
}

pub async fn write_json_message<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(msg).context("failed to serialize JSON frame")?;
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| anyhow!("frame too large to encode"))?;

    writer
        .write_all(&len.to_le_bytes())
        .await
        .context("failed to write frame length")?;
    writer
        .write_all(&payload)
        .await
        .context("failed to write frame payload")?;
    writer.flush().await.context("failed to flush frame")?;

    Ok(())
}
