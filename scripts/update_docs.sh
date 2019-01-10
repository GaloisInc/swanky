#!/bin/bash -e

rm -rf docs
cargo doc --no-deps --target-dir tmp
mv tmp/doc docs
rm -rf tmp
git add docs
