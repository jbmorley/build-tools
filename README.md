# Build Tools

Collection of convenience build tools

## Autocomplete

`build-tools` supports autocomplete using [`argcomplete`](https://kislyuk.github.io/argcomplete/):

1. Install `argcomplete` through your package manager of choice. For example,

  ```sh
  uv tool install argcomplete
  ```

2. Enable autocomplete by adding one of the following to your shell startup file (`~/.zshrc`,  `~/.bashrc`, etc):

- for just `build-tools`:

  ```sh
  eval "$(register-python-argcomplete build-tools)"
  ```

- or globally:

  ```sh
  activate-global-python-argcomplete
  ```

