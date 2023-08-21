#!/usr/bin/env bash
# We want to pass the --html-in-header argument to rustdoc. Unfortunately, cargo invokes rustdoc
# _both_ for running doctests and for generating documentation. When running doctests, the working
# directory is set to the root of the crate being tested and _not_ the workspace root. As a result,
# you can't specify a relative path to the html-in-header flag. And there's no option to set a
# rustdoc flag in the cargo config which resolves to an absolute path.
# 
# To work around this, we tell cargo to use this script as the rustdoc command. The path to the
# this script is computed relative to the workspace root, so it's not subject to this issue.
# 
# Thus, we can safely compute an _absolute_ path to the rustdoc-html-header.html file in this
# script.
exec rustdoc "$@" --html-in-header "$(realpath "$(dirname "$0")/rustdoc-html-header.html")"
