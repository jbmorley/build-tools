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

set -e
set -o pipefail
set -x
set -u

ROOT_DIRECTORY="$( cd "$( dirname "$( dirname "${BASH_SOURCE[0]}" )" )" &> /dev/null && pwd )"
BUILD_TOOLS="$ROOT_DIRECTORY/build-tools"

export LOCAL_TOOLS_PATH="$ROOT_DIRECTORY/.local-smoke-test"
export PYTHONUSERBASE="$LOCAL_TOOLS_PATH/python"
export PATH="$PYTHONUSERBASE/bin:$PATH"
export PYTHONPATH="$PYTHONUSERBASE"
export WORKON_HOME="$LOCAL_TOOLS_PATH"
export PIPENV_CUSTOM_VENV_NAME="venv"
export PIPENV_IGNORE_VIRTUALENVS=1
export PIPENV_PIPFILE="$ROOT_DIRECTORY/Pipfile"

# Explicitly disable in-project virtualenvs; without this Pipenv uses an
# existing ./.venv in the project root (if present) in preference to WORKON_HOME.
export PIPENV_VENV_IN_PROJECT=0

# Recreate the namespaced tools directory so the install starts clean.
if [ -d "$LOCAL_TOOLS_PATH" ] ; then
    rm -r "$LOCAL_TOOLS_PATH"
fi
mkdir -p "$PYTHONUSERBASE"

# Install Pipenv (locally) and the project dependencies.
pip install --user --upgrade pip pipenv wheel
pipenv install

# The CLI loads and reports its top-level usage.
"$BUILD_TOOLS" --help

# A representative command runs end-to-end and produces output; parsing it back
# round-trips through a second command, exercising the launcher twice.
BUILD_NUMBER="$("$BUILD_TOOLS" generate-build-number)"
if ! [[ "$BUILD_NUMBER" =~ ^[0-9]+$ ]] ; then
    echo "Expected a numeric build number but got '$BUILD_NUMBER'."
    exit 1
fi
"$BUILD_TOOLS" parse-build-number "$BUILD_NUMBER"
