# Icons

A monitor in sunglasses, because [futureburn](https://github.com/sp00nznet/futureburn)
is a CD in sunglasses and these are siblings. The viewer shades its eyes and glows blue;
the server has an antenna and glows green.

| File | What it is |
|---|---|
| `vncfree.png`, `vncfree-server.png` | The masters, 512px with a transparent background. |
| `vncfree.ico`, `vncfree-server.ico` | 16, 32, 48, 64, 128 and 256px, built from the masters. |
| `vncfree.rc`, `vncfree-server.rc` | One line each, naming the icon as resource `1`. |

`build.rs` compiles each `.rc` **for one binary**, because a Windows icon is a linked
resource rather than a file the program opens, and the two executables want different
ones. A missing resource compiler downgrades to a warning: an icon is not worth failing
a build over.

Resource `1` is deliberate. Explorer and the taskbar use the lowest-numbered icon in a
binary, so a higher number is quietly ignored.

## Redrawing them

The masters came out of [asset-forge](https://github.com/sp00nznet/asset-forge)'s
`txt2img` on a local ComfyUI, `zimage_turbo` at 1024x1024, then background removal and
downscaling. The prompt that produced these two:

> chunky cartoon computer monitor mascot with a face, cool black sunglasses across the
> screen, **[one hand shading its eyes looking into the distance | antenna on its head
> with radio signal arcs, one arm waving]**, noodle arms and legs, white high top
> sneakers with red laces, **[blue | green]** glowing screen, heavy black ink outline,
> flat vector cartoon style, retro 90s mascot sticker, full body centered, plain solid
> white background

Two things that matter if you regenerate:

- **Cut the background out by flooding in from the edges, not by keying out white.** The
  sneakers, the hands and the screen highlights are all white too, and a colour key
  punches holes straight through them. The black outline is what stops a flood fill
  getting inside the character.
- **Crop to the artwork before downscaling.** A render leaves a wide margin, and keeping
  it means the character is a handful of pixels across by the time it reaches 16px.
