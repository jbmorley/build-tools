#!/bin/bash

# Copyright (c) 2018-2026 Jason Morley
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Exercise the `create-keychain` command against the real macOS `security`
# tool. This is destructive to the keychain search list, so it is intended to
# run only on an ephemeral macOS CI runner, never on a development machine.

set -e
set -o pipefail
set -x
set -u

SCRIPTS_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIRECTORY="$( cd "$SCRIPTS_DIRECTORY/.." &> /dev/null && pwd )"
BUILD_TOOLS="$ROOT_DIRECTORY/build-tools"

source "$SCRIPTS_DIRECTORY/environment.sh"

WORK_DIRECTORY="$(mktemp -d)"
RANDOM_KEYCHAIN="$WORK_DIRECTORY/random.keychain"
PROVIDED_KEYCHAIN="$WORK_DIRECTORY/provided.keychain"
PASSWORD="correct-horse-battery-staple"

cleanup() {
    security delete-keychain "$RANDOM_KEYCHAIN" 2> /dev/null || true
    security delete-keychain "$PROVIDED_KEYCHAIN" 2> /dev/null || true
    rm -rf "$WORK_DIRECTORY"
}
trap cleanup EXIT

# Check creation and deletion.
"$BUILD_TOOLS" create-keychain "$RANDOM_KEYCHAIN"
"$BUILD_TOOLS" delete-keychain "$RANDOM_KEYCHAIN"

# Check we respect provided passwords.
printf '%s' "$PASSWORD" | "$BUILD_TOOLS" create-keychain --password "$PROVIDED_KEYCHAIN"
security unlock-keychain -p "$PASSWORD" "$PROVIDED_KEYCHAIN"
if security unlock-keychain -p "wrong-$PASSWORD" "$PROVIDED_KEYCHAIN" 2> /dev/null ; then
    echo "Keychain unlocked with an incorrect password; the provided password was not honoured."
    exit 1
fi
"$BUILD_TOOLS" delete-keychain "$PROVIDED_KEYCHAIN"
