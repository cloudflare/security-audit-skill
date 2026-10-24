# Troubleshooting

## "OS no-follow and nonblocking input protection is unavailable"

On Windows, Node may not expose `O_NOFOLLOW`/`O_NONBLOCK`. The validators fall back to an `lstat`-based symlink check and a regular open. If you still see this error, you are running an older build — update to the latest.

## CLI input is rejected

- Ensure the input file is a regular file, not a symlink or directory.
- Input must be UTF-8 and below the byte limit.
- Oversized arrays/nesting are rejected by design.

## Tests

Run:
```
node --test skills/security-audit/*.test.cjs
```
