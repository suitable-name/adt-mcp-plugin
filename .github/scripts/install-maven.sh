#!/usr/bin/env bash
# Downloads, verifies and unpacks Apache Maven into $RUNNER_TEMP and puts it on the PATH of
# the following workflow steps.
#
# Maven Central occasionally answers 404 for a file that exists (a CDN miss), and curl does not
# retry a 404 on its own, so every download retries all errors and then falls back to the
# Apache archive. The SHA-512 published by Apache guards whichever source answered.
#
# Usage: install-maven.sh <version> <sha512 of apache-maven-<version>-bin.tar.gz>
set -euo pipefail

version=${1:?Maven version}
sha512=${2:?SHA-512 of the binary tarball}
archive="apache-maven-${version}-bin.tar.gz"
sources=(
    "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${version}/${archive}"
    "https://archive.apache.org/dist/maven/maven-3/${version}/binaries/${archive}"
)

cd "${RUNNER_TEMP:?RUNNER_TEMP is not set}"
for source in "${sources[@]}"; do
    if curl --fail --silent --show-error --location \
        --retry 4 --retry-all-errors --retry-delay 5 --connect-timeout 20 \
        --output "$archive" "$source"; then
        if printf '%s  %s\n' "$sha512" "$archive" | sha512sum --check --status; then
            tar -xzf "$archive"
            echo "$RUNNER_TEMP/apache-maven-${version}/bin" >> "${GITHUB_PATH:?GITHUB_PATH is not set}"
            echo "Installed Maven ${version} from ${source}."
            exit 0
        fi
        echo "Checksum mismatch for ${source}; trying the next source." >&2
    else
        echo "Download failed from ${source}; trying the next source." >&2
    fi
    rm -f "$archive"
done
echo "Could not download a verified Maven ${version}." >&2
exit 1
