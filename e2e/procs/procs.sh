#!/bin/sh
# Список процессов nginx в контейнере: в образе нет ps, а после reload важно
# видеть, что старые воркеры действительно ушли.
#
#     docker compose exec -T nginx-1 sh /t/procs/procs.sh
for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    printf '%s\t' "${p#/proc/}"
    tr '\0' ' ' < "$p/cmdline"
    echo
done
