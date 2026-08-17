# Third-party notices

## testssl.sh

This container executes an unmodified copy of **testssl.sh 3.2.4** at commit
`97763a411c525720a5f9bd9d2cded416b10f210a`.

- Upstream project: https://github.com/testssl/testssl.sh
- Pinned source: https://github.com/testssl/testssl.sh/tree/97763a411c525720a5f9bd9d2cded416b10f210a
- License: GNU General Public License version 2 only (`GPL-2.0-only`)
- Copyright and warranty notices: retained in the upstream source tree and its
  `LICENSE` file

The complete, unmodified corresponding testssl.sh source is included in every
built image at `/opt/testssl`, together with the upstream license, data files,
mappings, documentation, and commit metadata. The Docker build verifies the
resolved commit before copying that tree. No testssl.sh source is copied into
the Cresswell HTTP service, and the service communicates with it as a separate
process through fixed command-line arguments and JSON output files.

The image lets the pinned testssl.sh release select its supplied
`bin/openssl.Linux.<architecture>` binary for legacy-capable coverage and its
normal system-OpenSSL shortcut where the upstream scanner requires modern
TLS 1.3 support. The Docker build fails if the bundled binary for the image
architecture is absent or non-executable. Distribution of the final image must
retain `/opt/testssl`, this notice, and the upstream `LICENSE` file.
