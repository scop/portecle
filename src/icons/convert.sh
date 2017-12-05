#!/bin/bash -e

 dpis=(    3     6     9    12    18      24      36      48      96)
sizes=(16x16 32x32 48x48 64x64 96x96 128x128 192x192 256x256 512x512)

for i in ${!dpis[@]}; do
    mkdir -p ${sizes[i]}
    for suffix in -alt1 -alt2 -alt3; do
        inkscape \
            --export-png=${sizes[i]}/portecle$suffix.png \
            --export-dpi=${dpis[i]} \
            svg/portecle$suffix.svg
    done
done

n=$(nproc 2>/dev/null || echo 1)
find . -name "*.png" -printf "'%p' '%p'\n" | xargs -L 1 -P $n zopflipng -ym
