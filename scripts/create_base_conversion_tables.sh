#!/bin/bash

set -e

nbits=16

script_dir="$(dirname $(readlink -f ${BASH_SOURCE[0]}))"
gen_table="$script_dir/make_lookup_table.pl"

file=$(readlink -f "$script_dir/../base_conversion/cbits/lookup_tables.c")

min=3
max=113

[[ -f $file ]] && rm -i $file

cat << EOF >> $file
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

EOF

for mod in $(seq $min $max); do
    echo "generating table $mod (max=$max)"
    $gen_table tab $nbits $mod >>$file 
    echo >>$file
done

echo "generating functions"

cat << EOF >> $file
uint8_t* c_get_table(uint8_t mod) {
    switch (mod) {
EOF

for mod in $(seq $min $max); do
    echo "        case $mod: return (uint8_t*)BASE_$mod;" >>$file
done

cat << EOF >> $file
        default: return NULL;
    }
}

size_t c_num_digits(uint8_t mod) {
    switch (mod) {
EOF

for mod in $(seq $min $max); do
    n=$($gen_table num $nbits $mod)
    echo "        case $mod: return $n;" >>$file
done

cat << EOF >> $file
        default: return 0;
    }
}
EOF

echo "filename=$file"
