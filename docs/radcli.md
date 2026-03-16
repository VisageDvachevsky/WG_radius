# radcli dependency

`wg_radius` requires `radcli >= 1.4.0`.

Reason:
- strict Phase 1 compliance requires `Message-Authenticator` in `Access-Request`;
- older `radcli` releases such as `1.2.11` do not add it for the current auth path;
- the real Phase 1 integration test checks this explicitly.

Local build against a forked `radcli` install:

```bash
git clone https://github.com/VisageDvachevsky/radcli.git /tmp/radcli
cd /tmp/radcli
./autogen.sh
./configure --prefix=/tmp/radcli-install
make -j"$(nproc)"
make install
```

Configure `wg_radius` against that install:

```bash
cd /path/to/WG_radius
PKG_CONFIG_PATH=/tmp/radcli-install/lib/pkgconfig \
cmake -S . -B build -DWG_RADIUS_ENABLE_INTEGRATION_TESTS=ON
cmake --build build
```

Run the real Phase 1 integration:

```bash
LD_LIBRARY_PATH=/tmp/radcli-install/lib \
WG_RADIUS_IT_SUDO_PASSWORD=... \
ctest --test-dir build -R wg_radius_phase1_radius_integration --output-on-failure
```
