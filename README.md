# gitrust

gitrust exposes an HTTP interface to perform git actions.

It is intended to be used as a backend for https://github.com/Kegsay/github-pull-review filling in areas where the Github APIs aren't sufficient for its needs, e.g. to perform squash-merges.

It is my first Rust, so is almost certainly terrible.

## Building

You need the rust and cargo tools. Then simply run:

```
cargo build --release
```

and gitrust will be output to target/release/gitrust.

## Flags

Some flags are required. See the source for details. review.rocks runs with this configuration:

```
gitrust -p 8080 -i 0.0.0.0 -h review.rocks --oauth_client_id=[GITHUB_CLIENT_ID] --oauth_client_secret=[GITHUB_CLIENT_SECRET] --oauth_redirect_path=[GITHUB_REDIRECT_PATH] --whitelisted_domains=review.rocks
```
