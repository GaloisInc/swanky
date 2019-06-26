#!/usr/bin/env bash

set -e

cargo doc --all-features --no-deps --target-dir tmp
rm -rf docs
mv tmp/doc docs
rm -rf tmp

git add docs
git commit -m "update docs"
