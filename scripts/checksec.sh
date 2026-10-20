#!/usr/bin/env bash
# Verifies the hardening flags actually landed in a binary, using readelf
# only: PIE, full RELRO (GNU_RELRO + BIND_NOW), NX stack, stack protector,
# FORTIFY (_chk symbols), CET (IBT/SHSTK property note).
# Usage: checksec.sh BINARY...
set -uo pipefail
fail=0
for bin in "$@"; do
  hdr=$(readelf -h "$bin"); ph=$(readelf -lW "$bin"); dyn=$(readelf -dW "$bin"); syms=$(readelf -sW --dyn-syms "$bin")
  notes=$(readelf -nW "$bin")
  check() { if eval "$2"; then printf "  %-16s yes\n" "$1"; else printf "  %-16s NO\n" "$1"; fail=1; fi; }
  echo "$bin"
  check PIE               'grep -q "Type:.*DYN" <<<"$hdr"'
  check RELRO             'grep -q GNU_RELRO <<<"$ph"'
  check BIND_NOW          'grep -Eq "BIND_NOW|FLAGS_1.*NOW" <<<"$dyn"'
  check NX-stack          'grep -A1 GNU_STACK <<<"$ph" | grep -qv "RWE"'
  check stack-protector   'grep -q __stack_chk_fail <<<"$syms"'
  check FORTIFY           'grep -Eq "__[a-z_]+_chk@" <<<"$syms"'
  check CET-IBT/SHSTK     'grep -q "IBT, SHSTK" <<<"$notes"'
  printf "  %-16s %s\n" "fortified fns" "$(grep -Eo '__[a-z_]+_chk' <<<"$syms" | grep -v '^__stack_chk$' | sort -u | tr '\n' ' ')"
done
exit $fail
