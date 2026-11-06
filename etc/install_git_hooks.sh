#!/bin/sh

HERE=$(cd $(dirname $0); pwd)
ROOT=${HERE}/..

# This script will configure Git to use all of the available hooks.

# Set the location for Git Hooks to be used.
git config --local core.hooksPath ${ROOT}/etc/hooks
