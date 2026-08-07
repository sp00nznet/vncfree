//! Gives each executable its own icon.
//!
//! A Windows icon is a linked resource, not a file the program reads, so it has to be
//! compiled in at build time. The two binaries want *different* icons, which is why
//! this uses `compile_for` per binary rather than setting one resource for the whole
//! crate: that emits a link argument aimed at one binary instead of all of them.
//!
//! Nothing here runs anywhere but Windows, and neither binary is useful anywhere else.

fn main() {
    println!("cargo:rerun-if-changed=assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    for (script, bin) in [
        ("assets/vncfree.rc", "vncfree"),
        ("assets/vncfree-server.rc", "vncfree-server"),
    ] {
        // A missing resource compiler should not stop the build. The icon is the only
        // thing lost, and refusing to produce a working program over decoration would
        // be the wrong trade.
        if let Err(e) =
            embed_resource::compile_for(script, [bin], embed_resource::NONE).manifest_optional()
        {
            println!("cargo:warning=no icon for {bin}: {e}");
        }
    }
}
