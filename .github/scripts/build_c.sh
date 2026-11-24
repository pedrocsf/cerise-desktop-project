#!/usr/bin/env bash
set -euo pipefail

output_directory="${1:-build}"
mkdir -p "$output_directory"

base_flags=(-std=gnu11 -Wall -Wextra -O2 -Ivirtual_machine)
link_flags=(-lcrypto -lpthread)
status=0

while IFS= read -r -d '' source_file; do
  target="$output_directory/$(basename "${source_file%.c}")"
  flags=("${base_flags[@]}")
  if grep -q '#include "frame_auth.h"' "$source_file"; then
    flags+=(-Werror)
  fi
  echo "::group::$source_file ${flags[*]}"
  if ! gcc "${flags[@]}" -o "$target" "$source_file" "${link_flags[@]}"; then
    echo "::error file=$source_file::build failed"
    status=1
  fi
  echo "::endgroup::"
done < <(git ls-files -z '*.c')

exit "$status"
