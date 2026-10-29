# Shared helpers for tools/vendor/record and tools/vendor/verify. Sourced, not
# executed. The layout is the zu* family's (#18): manifest.tsv names each
# vendored source, checksums.sha256 pins every byte of src/vendor/.

# sha256 of a file, bare hex, on macOS and Linux alike.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        echo "no sha256sum or shasum available" >&2
        exit 1
    fi
}

# The manifest's source names, one per line.
manifest_sources() {
    awk 'NR > 1 && NF { print $1 }' FS='\t' tools/vendor/manifest.tsv
}

# Every vendored file, sorted, repo-relative. Build products are not vendored
# (an in-place `R CMD INSTALL .` leaves .o files beside the sources).
vendored_files() {
    find src/vendor -type f ! -name '*.o' ! -name '*.so' ! -name '*.dll' \
        | LC_ALL=C sort
}
