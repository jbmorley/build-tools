#!/usr/bin/env python3

# Copyright (c) 2018-2021 InSeven Limited
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

import argparse
import base64
import datetime
import functools
import glob
import json
import logging
import os
import re
import secrets
import subprocess
import shutil
import sys
import tempfile

import lxml

from lxml import etree as ET

# import xml.etree.ElementTree as ET


verbose = '--verbose' in sys.argv[1:] or '-v' in sys.argv[1:]
logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="[%(levelname)s] %(message)s")


PROFILES_DIRECTORY = os.path.expanduser("~/Library/MobileDevice/Provisioning Profiles")

COMMANDS = {}


class Command(object):

    def __init__(self, name, help, arguments, callback):
        self.name = name
        self.help = help
        self.arguments = arguments
        self.callback = callback

class Argument(object):

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def command(name, help="", arguments=[]):
    def wrapper(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            return fn(*args, **kwargs)
        COMMANDS[name] = Command(name, help, arguments, inner)
        return inner
    return wrapper


class CommandParser(object):

    def __init__(self, *args, **kwargs):
        self.parser = argparse.ArgumentParser(*args, **kwargs)
        subparsers = self.parser.add_subparsers(help="command")
        for name, command in COMMANDS.items():
            subparser = subparsers.add_parser(command.name, help=command.help)
            for argument in command.arguments:
                subparser.add_argument(*(argument.args), **(argument.kwargs))
            subparser.set_defaults(fn=command.callback)

    def run(self):
        options = self.parser.parse_args()
        if 'fn' not in options:
            logging.error("No command specified.")
            exit(1)
        options.fn(options)


def list_keychains():
    keychains = subprocess.check_output(["security", "list-keychains", "-d", "user"]).decode("utf-8").strip().split("\n")
    keychains = [json.loads(keychain) for keychain in keychains]  # list-keychains quotes the strings
    return keychains


def create_keychain(path, password):
    subprocess.check_call(["security", "create-keychain", "-p", "12345678", path])
    subprocess.check_call(["security", "set-keychain-settings", "-lut", "21600", path])


def unlock_keychain(path, password):
    subprocess.check_call(["security", "unlock-keychain", "-p", password, path])


def add_keychain(path):
    subprocess.check_call(["security", "list-keychains", "-d", "user", "-s"] + list_keychains() + [path])


@command("create-keychain", help="safely create a temporary keychain", arguments=[
    Argument("path", help="path at which to create the keychain"),
    Argument("--password", "-p", action="store_true", default=False, help="read password from stdin")
])
def command_create_keychain(options):
    path = os.path.abspath(options.path)
    logging.info("Creating keychain '%s'...", path)
    password = secrets.token_hex()
    if options.password:
        password = sys.stdin.read().strip()
    create_keychain(path, password)
    add_keychain(path)
    unlock_keychain(path, password)


@command("delete-keychain", help="safely delete a temporary keychain removing it from the active set", arguments=[
    Argument("path", help="path of the keychain to delete")
])
def command_delete_keychain(options):
    path = os.path.abspath(options.path)
    logging.info("Deleting keychain '%s'...", path)
    subprocess.check_call(["security", "delete-keychain", path])


@command("verify-notarized-zip", help="unpack a compressed Mac app and verify the notarization", arguments=[
    Argument("path", help="path to the zip file to verify")
])
def command_verify_notarized_zip(options):
    path = os.path.abspath(options.path)
    with tempfile.TemporaryDirectory() as directory:
        subprocess.check_call(["unzip", "-d", directory, "-q", path])
        app_path = glob.glob(directory + "/*.app")[0]
        try:
            result = subprocess.run(["spctl", "-a", "-v", app_path], capture_output=True)
            result.check_returncode()
        except subprocess.CalledProcessError as e:
            logging.error(e.stderr.decode("utf-8").strip())
            exit("Failed to verify bundle.")


@command("synthesize-build-number", help="synthesize a build number (YYmmddHHMM + 8 digit integer representation of a 6 digit Git SHA")
def command_synthesize_build_number(options):
    utc_time = datetime.datetime.utcnow()
    git_sha = subprocess.check_output(["git", "rev-parse", "--short=6", "HEAD"]).decode("utf-8").strip()
    git_sha_int = int(git_sha, 16)
    build_number = f"{utc_time.strftime('%y%m%d%H%M')}{git_sha_int:08}"
    print(build_number)


@command("import-base64-certificate", help="import base64 encoded certificate to a specific keychain", arguments=[
    Argument("path", help="path of the keychain to update"),
    Argument("certificate", help="base64 encoded PKCS12 (.p12) certificate"),
    Argument("--password", "-p", action="store_true", default=False, help="read password from stdin"),
])
def command_import_certificate(options):

    path = os.path.abspath(options.path)
    if options.password:
        password = sys.stdin.read().strip()
    certificate = base64.b64decode(options.certificate)

    with tempfile.TemporaryDirectory() as directory:
        certificate_path = os.path.join(directory, "certificate.p12")
        with open(certificate_path, "wb") as fh:
            fh.write(certificate)

        parameters = [
            "security", "import",
            certificate_path,
            "-A",
            "-t", "cert",
            "-f", "pkcs12",
            "-k", path]

        if options.password:
            parameters.extend(["-P", password])

        subprocess.check_call(parameters)


@command("install-provisioning-profile", help="install provisioining profile for the current user", arguments=[
    Argument("path", help="path of profile to install"),
])
def command_install_provisioning_profile(options):
    path = os.path.abspath(options.path)
    expression = re.compile(r'<plist version="1\.0">(.*)<\/plist>', re.MULTILINE | re.DOTALL)
    with open(path, "rb") as fh:
        contents = fh.read().decode('utf-8', 'ignore')
        match = expression.search(contents)
        plist = ET.fromstring(match.group(1))
        uuid = plist.xpath("key[.='UUID']/following-sibling::string")[0].text
    _, ext = os.path.splitext(path)
    destination_name = f"{uuid}{ext}"
    destination_path = os.path.join(PROFILES_DIRECTORY, destination_name)
    if not os.path.exists(PROFILES_DIRECTORY):
        logging.info("Creating profiles directory...")
        os.makedirs(PROFILES_DIRECTORY)
    if os.path.exists(destination_path):
        logging.info("Provisioning profile '%s' already exists.", destination_name)
        return
    logging.info("Installing profile '%s' to '%s'...", os.path.basename(path), destination_path)
    shutil.copy(path, destination_path)


def main():
    parser = CommandParser(description="Create and register a temporary keychain for development")
    parser.run()


if __name__ == "__main__":
    main()
