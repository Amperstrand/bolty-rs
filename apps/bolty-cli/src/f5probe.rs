use bolty_ntag::Transport;

use crate::common::gen_rnd_a;

pub async fn cmd_f5probe<T: Transport>(transport: &mut T) -> anyhow::Result<()>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let r = bolty_ntag::f5probe(transport, gen_rnd_a()?)
        .await
        .map_err(|e| anyhow::anyhow!("f5probe: {e:?}"))?;
    let ((f5a, ad), (f5w, wd)) = r;
    println!("read-interleave:  F5 ok={f5a}/3, AD ok={ad}/3");
    println!("write-interleave: F5 ok={f5w}/2, 8D ok={wd}/1");
    Ok(())
}
