# krds

small tool that looks for common rootkit footprints on linux.

it mostly cross-checks stuff the kernel exposes (`/proc`, `/sys`) because
rootkits often hide from one place and forget another. also does some
basic module/socket/integrity checks.

```
cargo build --release
sudo ./target/release/krds scan
sudo ./target/release/krds scan --collect
```

writes a report under `output/`. first integrity run saves a baseline;
later runs compare against it.

needs root for useful results. not magic, if the kernel is owned hard
enough, this can lie to you too.
