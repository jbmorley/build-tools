#!/usr/bin/env python3

# Copyright (c) 2018-2025 Jason Morley
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
import contextlib
import datetime
import fnmatch
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
import time

import requests

from xml.dom import minidom

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


# TODO: Is this used anywhere?
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


@command("notarize", help="notarize and staple a macOS app for distribution", arguments=[
    Argument("path", help="path to the app bundle to notarize"),
    Argument("--key", required=True, help="path of the App Store Connect API key (required)"),
    Argument("--key-id", required=True, help="App Store Connect API key id (required)"),
    Argument("--issuer", required=True, help="App Store Connect API key issuer id (required)"),
    Argument("--log", help="fetch the notarization log and save to the specified path"),
    Argument("--skip-staple", action="store_true", default=False, help="skip stapling (useful for CLI apps)"),
])
def command_notarize(options):
    path = os.path.abspath(options.path)
    key_path = os.path.abspath(options.key)
    log_path = os.path.abspath(options.log) if options.log else None

    # Verify the app signature before continuing.
    logging.info("Verifying signature of '%s'...", path)
    verify_signature(path)

    with tempfile.TemporaryDirectory() as temporary_directory:

        # Compress the app for submission.
        zip_path = os.path.join(temporary_directory, "release.zip")
        app_directory, app_basename = os.path.split(path)
        logging.info("Compressing '%s' to '%s'...", app_basename, zip_path)
        with contextlib.chdir(app_directory):
            subprocess.check_call([
                "zip",
                "--symlinks",
                "-r",
                zip_path,
                app_basename,
            ])

        # Notarize.
        logging.info("Notarizing '%s'...", zip_path)
        output = subprocess.check_output([
            "xcrun", "notarytool",
            "submit", zip_path,
            "--key", key_path,
            "--key-id", options.key_id,
            "--issuer", options.issuer,
            "--output-format", "json",
            "--wait",
        ]).decode("utf-8")
        response = json.loads(output)
        response_id = response["id"]
        response_status = response["status"]

    # Download the log and write it to disk.
    if log_path is not None:
        logging.info("Fetching notarization log with id '%s'...", response["id"])
        output = subprocess.check_output([
            "xcrun", "notarytool", "log",
            "--key", key_path,
            "--key-id", options.key_id,
            "--issuer", options.issuer,
            response["id"],
        ]).decode("utf-8")
        with open(log_path, "w") as fh:
            fh.write(output)

    # Check to see if we should continue.
    if response["status"] != "Accepted":
        exit("Failed to notarize app.")

    # Staple and validate the app; this bakes the notarization into the app in case the device trying to run it can't do
    # an online check with Apple's servers for some reason.
    if not options.skip_staple:
        subprocess.check_call([
            "xcrun", "stapler",
            "staple", path,
        ])
        subprocess.check_call([
            "xcrun", "stapler",
            "validate", path,
        ])

    # Next up, we perform a belt-and-braces check that the app validates after stapling.
    verify_signature(path)


def verify_signature(path):
    subprocess.check_call([
        "codesign", "--verify", "--deep", "--strict", "--verbose=2", path,
    ])
    subprocess.check_call([
        "codesign", "--display", "-vvv", path,
    ])


@command("generate-build-number", help="synthesize a build number (YYmmddHHMM + 8 digit integer representation of a 6 digit Git SHA")
def command_generate_build_number(options):
    utc_time = datetime.datetime.now(datetime.UTC)
    # Unhelpfully, the '--short=length' option guarantees to give an object name _no shorter_ than the requested length
    # will happily, on occasion, return one that's longer, meaning we have to limit this to 6 characters ourselves.
    git_sha = subprocess.check_output(["git", "rev-parse", "--short=6", "HEAD"]).decode("utf-8").strip()[:6]
    git_sha_int = int(git_sha, 16)
    build_number = f"{utc_time.strftime('%y%m%d%H%M')}{git_sha_int:08}"
    print(build_number)


@command("latest-github-release", help="get the URL for an asset from the latest GitHub release matching a pattern (respects `GITHUB_TOKEN` environment variable)", arguments=[
    Argument("owner"),
    Argument("repository"),
    Argument("pattern"),
])
def command_latest_github_release(options):

    # Default API headers.
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Use a GitHub token if it's present in the environment as this is likely to have fewer rate limits.
    if "GITHUB_TOKEN" in os.environ:
        headers["Authorization"] = f"Bearer {os.environ["GITHUB_TOKEN"]}"

    # Fetch the required data with an exponential backoff (max 5m) if we hit a 403 rate limit.
    attempt = 1
    while True:
        response = requests.get(f"https://api.github.com/repos/{options.owner}/{options.repository}/releases/latest", headers=headers)
        if response.status_code == 200:
            break
        elif response.status_code == 403:
            sleep_duration_s = min(300, 2 ** attempt)
            logging.info(f"Waiting {sleep_duration_s}s for GitHub API rate limits...")
            time.sleep(sleep_duration_s)
            attempt += 1
            continue
        else:
            response.raise_for_status()

    # Check the assets for the requested pattern.
    regex = re.compile(fnmatch.translate(options.pattern))
    for asset in response.json()["assets"]:
        if not regex.match(asset["name"]):
            continue
        print(asset["browser_download_url"])
        return

    exit(f"Failed to find asset with pattern '{options.pattern}'.")


@command("parse-build-number", help="parse a build nunmber to retrieve the date and Git SHA", arguments=[
    Argument("build", help="build number to parse")
])
def command_synthesize_build_number(options):
    date_string, sha_string = options.build[:10], options.build[10:]
    date = datetime.datetime.strptime(date_string, "%y%m%d%H%M")
    sha = "%06x" % int(sha_string)
    print("%s (UTC)" % date)
    print(sha)


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
    Argument("path", nargs="+", help="path of profile to install"),
])
def command_install_provisioning_profile(options):
    for path in options.path:
        path = os.path.abspath(path)
        expression = re.compile(r'<plist version="1\.0">(.*)<\/plist>', re.MULTILINE | re.DOTALL)
        with open(path, "rb") as fh:
            contents = fh.read().decode('utf-8', 'ignore')
            match = expression.search(contents)
            dom = minidom.parseString(match.group(1))
            root = dom.getElementsByTagName("dict")[0]
            uuid = None
            found_uuid_key = False
            for child in root.childNodes:
                if child.nodeName == "key" and child.childNodes[0].data == "UUID":
                    found_uuid_key = True
                    continue
                elif child.nodeName == "string" and found_uuid_key:
                    uuid = child.childNodes[0].data
                    break
            if uuid is None:
                exit("Unable to determine profile UUID.")
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


@command("add-artifact", help="add an artifact to the artifact manifest", arguments=[
    Argument("manifest", help="manifest to create or update"),
    Argument("--project", required=True, help="id of the project to add; should be consistent across all artifacts for a specific project"),
    Argument("--version", required=True, help="version of the project"),
    Argument("--build-number", required=True, help="build number of the project"),
    Argument("--sha", required=True, help="git sha associated with the artifact"),
    Argument("--os", required=True, choices=["macos", "debian", "ubuntu"], help="os (one of macos, debian, or ubuntu)"),
    Argument("--os-version", required=True, help="os version (e.g., 26, 24.04, etc)"),
    Argument("--os-codename", required=True, help="os codename (e.g., tahoe, noble, etc); repeat the os version if not relevant"),
    Argument("--architecture", required=True, choices=["all", "arm64", "aarch64", "x86_64"], help="target os architecture"),
    Argument("--name", help="filename of the asset; inferred from the path if not provided"),
    Argument("--path", required=True, help="path to the artifact (relative or absolute); in the case of GitHub releases this should be the assset filename"),
    Argument("--format", required=True, choices=["deb", "pkg", "zip"], help="artifact format (deb|pkg|zip)"),
])
def command_add_artifact(options):
    manifest_path = os.path.abspath(options.manifest)

    # Load any existing manifest.
    manifest = []
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as fh:
            manifest = json.load(fh)

    name = options.name if options.name else os.path.basename(options.path)

    # Append the new artifact.
    manifest.append({
        "project": options.project,
        "version": options.version,
        "build_number": options.build_number,
        "sha": options.sha,
        "os": options.os,
        "os_version": options.os_version,
        "os_codename": options.os_codename,
        "architecture": options.architecture,
        "name": name,
        "path": options.path,
        "format": options.format,
    })

    # Write the updated manifest.
    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=4)
        fh.write("\n")


def main():
    parser = CommandParser(description="Create and register a temporary keychain for development")
    parser.run()


if __name__ == "__main__":
    main()
