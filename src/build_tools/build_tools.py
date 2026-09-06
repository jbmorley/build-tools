#!/usr/bin/env python3

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

import base64
import collections
import concurrent.futures
import contextlib
import datetime
import fnmatch
import functools
import glob
import hashlib
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

from dataclasses import dataclass

import fastcommand
import requests

from xml.dom import minidom

verbose = '--verbose' in sys.argv[1:] or '-v' in sys.argv[1:]
logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="[%(levelname)s] %(message)s")


PROFILES_DIRECTORY = os.path.expanduser("~/Library/MobileDevice/Provisioning Profiles")


def shasum(path):
    sha256 = hashlib.sha256()
    if os.path.isdir(path):
        for f in sorted(listdir(path, include_hidden=False)):
            sha256.update(shasum(os.path.join(path, f)).encode('utf-8'))
    else:
        with open(path, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha256.update(data)
    return sha256.hexdigest()


def list_keychains():
    keychains = subprocess.check_output(["security", "list-keychains", "-d", "user"]).decode("utf-8").strip().split("\n")
    keychains = [json.loads(keychain) for keychain in keychains]  # list-keychains quotes the strings
    return keychains


def create_keychain(path, password):
    subprocess.check_call(["security", "create-keychain", "-p", password, path])
    subprocess.check_call(["security", "set-keychain-settings", "-lut", "21600", path])


def unlock_keychain(path, password):
    subprocess.check_call(["security", "unlock-keychain", "-p", password, path])


def add_keychain(path):
    subprocess.check_call(["security", "list-keychains", "-d", "user", "-s"] + list_keychains() + [path])


@fastcommand.command("create-keychain", help="safely create a temporary keychain", arguments=[
    fastcommand.Argument("path", help="path at which to create the keychain"),
    fastcommand.Argument("--password", "-p", action="store_true", default=False, help="read password from stdin")
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


@fastcommand.command("delete-keychain", help="safely delete a temporary keychain removing it from the active set", arguments=[
    fastcommand.Argument("path", help="path of the keychain to delete")
])
def command_delete_keychain(options):
    path = os.path.abspath(options.path)
    logging.info("Deleting keychain '%s'...", path)
    subprocess.check_call(["security", "delete-keychain", path])


# TODO: Is this used anywhere?
@fastcommand.command("verify-notarized-zip", help="unpack a compressed Mac app and verify the notarization", arguments=[
    fastcommand.Argument("path", help="path to the zip file to verify")
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


@fastcommand.command("notarize", help="notarize (and staple where appropriate) one or more macOS build artifacts for distribution", arguments=[
    fastcommand.Argument("path", nargs="+", help="path to the app bundle or binary to notarize"),
    fastcommand.Argument("--key", required=True, help="path of the App Store Connect API key (required)"),
    fastcommand.Argument("--key-id", required=True, help="App Store Connect API key id (required)"),
    fastcommand.Argument("--issuer", required=True, help="App Store Connect API key issuer id (required)"),
    fastcommand.Argument("--log-directory", help="write a notarization log for each path to this directory"),
])
def command_notarize(options):
    key_path = os.path.abspath(options.key)
    log_directory = os.path.abspath(options.log_directory) if options.log_directory else None
    if log_directory is not None:
        os.makedirs(log_directory, exist_ok=True)

    paths = [os.path.abspath(path) for path in options.path]

    def notarize_path(path):
        log_path = None
        if log_directory is not None:
            log_path = os.path.join(log_directory, f"{os.path.basename(path)}-notarization-log.json")
        notarize(path, key_path=key_path, key_id=options.key_id, issuer=options.issuer, log_path=log_path)

    # Notarize in parallel since Apple's servers are slow.
    errors = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(paths)) as executor:
        futures = {executor.submit(notarize_path, path): path for path in paths}
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                future.result()
            except Exception as e:
                errors[path] = e

    if errors:
        for path, error in errors.items():
            logging.error("Failed to notarize '%s': %s", path, error)
        exit(f"Failed to notarize {len(errors)} of {len(paths)} artifact(s).")


def notarize(path, key_path, key_id, issuer, log_path=None):

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
            "--key-id", key_id,
            "--issuer", issuer,
            "--output-format", "json",
            "--wait",
        ]).decode("utf-8")
        response = json.loads(output)

    # Download the log and write it to disk.
    if log_path is not None:
        logging.info("Fetching notarization log with id '%s'...", response["id"])
        output = subprocess.check_output([
            "xcrun", "notarytool", "log",
            "--key", key_path,
            "--key-id", key_id,
            "--issuer", issuer,
            response["id"],
        ]).decode("utf-8")
        with open(log_path, "w") as fh:
            fh.write(output)

    # Check to see if we should continue.
    if response["status"] != "Accepted":
        raise RuntimeError(f"notarization status was '{response['status']}', expected 'Accepted'")

    # Staple and validate bundles; this bakes the notarization into the app in case the device trying to run it can't do
    # an online check with Apple's servers for some reason.
    if os.path.isdir(path):
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


@fastcommand.command("generate-build-number", help="synthesize a build number (YYmmddHHMM + 8 digit integer representation of a 6 digit Git SHA")
def command_generate_build_number(options):
    utc_time = datetime.datetime.now(datetime.UTC)
    # Unhelpfully, the '--short=length' option guarantees to give an object name _no shorter_ than the requested length
    # will happily, on occasion, return one that's longer, meaning we have to limit this to 6 characters ourselves.
    git_sha = subprocess.check_output(["git", "rev-parse", "--short=6", "HEAD"]).decode("utf-8").strip()[:6]
    git_sha_int = int(git_sha, 16)
    build_number = f"{utc_time.strftime('%y%m%d%H%M')}{git_sha_int:08}"
    print(build_number)


def github_headers():
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if "GITHUB_TOKEN" in os.environ:
        headers["Authorization"] = f"Bearer {os.environ["GITHUB_TOKEN"]}"
    return headers


def github_get(url, *args, **kwargs):
    kwargs["headers"] = github_headers()
    attempt = 1
    while True:
        response = requests.get(url, *args, **kwargs)
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
    return response


def github_get_paginated(url, *args, **kwargs):
    response = github_get(url, *args, **kwargs)
    while True:
        for item in response.json():
            yield item
        if not "next" in response.links:
            return
        response = github_get(response.links["next"]["url"], *args, **kwargs)


def filter_github_assets(assets, pattern):
    regex = re.compile(fnmatch.translate(pattern))
    return [asset for asset in assets if regex.match(asset["name"])]


@fastcommand.command("latest-github-release",
                     help="get the URL for an asset from the latest GitHub release matching a pattern (respects `GITHUB_TOKEN` environment variable)",
                     arguments=[
                         fastcommand.Argument("owner"),
                         fastcommand.Argument("repository"),
                         fastcommand.Argument("pattern"),
                    ])
def command_latest_github_release(options):
    release = github_get(f"https://api.github.com/repos/{options.owner}/{options.repository}/releases/latest").json()
    releases = filter_github_assets(release["assets"], options.pattern)
    if not releases:
        exit(f"Failed to find asset with pattern '{options.pattern}'.")
    print(releases[0]["browser_download_url"])


@fastcommand.command("github-releases",
                     help="download the releases from GitHub (respects `GITHUB_TOKEN` environment variable",
                     arguments=[
                         fastcommand.Argument("owner"),
                         fastcommand.Argument("repository"),
                         fastcommand.Argument("--synthesize-manifests", help="add additional data to releases without manifests using pattern matching"),
                         fastcommand.Argument("--output"),
                     ])
def command_github_releases(options):
    manifest_definition = {}
    if options.synthesize_manifests:
        with open(os.path.abspath(options.synthesize_manifests)) as fh:
            manifest_definition = json.load(fh)

    def extract_artifact(asset, git_sha):
        artifact = {
            "name": asset["name"],
            "path": asset["name"],
            "supports": [],
        }

        # Augment the artifact using the manifest definition; otherwise exclude it.
        matches_definition = False
        for pattern, metadata in manifest_definition.items():
            pattern_re = re.compile(fnmatch.translate(pattern))
            if pattern_re.match(artifact["name"]):
                artifact = {**artifact, **metadata}
                matches_definition = True
                break
        if not matches_definition:
            return None

        # Add the digest.
        if "digest" in asset and asset["digest"] is not None:
            digest_type, digest = asset["digest"].split(":")
            if digest_type != "sha256":
                raise AssertionError(f"Unsupported digest type '{digest_type}'")
            artifact["sha256"] = digest

        # Extract the version and associated metadata if we can.
        asset_name_match = re.search(r"(\d+\.\d+\.\d+)-(\d+)", asset["name"])
        if not asset_name_match:
            return artifact
        build = parse_build_number(asset_name_match.group(2))
        artifact["version"] = asset_name_match.group(1)
        artifact["build_number"] = build.number
        artifact["git_sha"] = git_sha

        return artifact

    def extract_keys(dictionaries, keys):
        """Extract keys from a list of dictionaries iff the values are identical or absent across all dictionaries."""
        result = {}
        if len(dictionaries) > 0:
            for key in keys:
                values = {dictionary[key] for dictionary in dictionaries if key in dictionary}
                value = values.pop() if len(values) == 1 else None
                if value is None:
                    continue
                result[key] = value
        return result

    def expand_build_number_metadata(artifact, base_url):
        """Parse the build number and add any additional metadata to the dictionary."""
        if "build_number" not in artifact:
            return artifact
        build = parse_build_number(artifact["build_number"])
        artifact["date"] = build.date.replace(tzinfo=datetime.timezone.utc).isoformat()
        artifact["time_zone"] = "UTC"
        artifact["url"] = f"{base_url}/{artifact["name"]}"
        return artifact

    def augment_manifest(manifest, release):
        """Augment release metadata with the release data from GitHub."""

        manifest = dict(manifest)

        # Expand implicit artifact metadata.
        base_url = f"https://github.com/{options.owner}/{options.repository}/releases/download/{release["name"]}"
        manifest["artifacts"] = [expand_build_number_metadata(artifact, base_url) for artifact in manifest["artifacts"]]

        # Check we've managed to find a build number in at least one of assets.
        asset_metadata = extract_keys(manifest["artifacts"], ["version", "build_number", "git_sha"])
        if manifest["artifacts"] and "build_number" not in asset_metadata:
            exit(f"Failed to find build number in assets ({[asset["name"] for asset in manifest["artifacts"]]}) for release '{release["name"]}' ({release["html_url"]}).")

        # Support version 1 manifests.
        # N.B. If we don't have any artifacts, then we have to use the release to get the version number.
        if manifest["version"] == 1:
            if manifest["artifacts"]:
                manifest["metadata"] = extract_keys(manifest["artifacts"], ["version", "build_number", "git_sha"])
            else:
                manifest["metadata"] = {
                    "version": release["name"]
                }

        # Add GitHub metadata.
        manifest["is_released"] = not (release["prerelease"] or release["draft"])
        manifest["url"] = release["html_url"]
        manifest["changes"] = dict(changes)

        # Expand the build number metadata if we have one.
        if "build_number" in manifest["metadata"]:
            build = parse_build_number(manifest["metadata"]["build_number"])
            manifest["commit_url"] = f"https://github.com/{options.owner}/{options.repository}/commit/{manifest["metadata"]["git_sha"]}"
            manifest["date"] = build.date.replace(tzinfo=datetime.timezone.utc).isoformat()
            manifest["time_zone"] = "UTC"

        return manifest

    def parse_changes(release):
        """Generate a list of changes from the release description."""

        section_re = re.compile(r"^\*\*(.+)\*\*$")
        change_re = re.compile(r"^-\s+(.+?)(\s\(#(\d+)\))?$")

        changes = collections.defaultdict(list)
        section = "default"
        for line in [line for line in release["body"].split("\n") if line]:
            title_match = section_re.match(line)
            change_match = change_re.match(line)
            if title_match:
                section = title_match.group(1).lower()
            elif change_match:
                change = {
                    "description": change_match.group(1),
                }
                if change_match.group(3):
                    pr_id = change_match.group(3)
                    change["pr"] = {
                        "id": pr_id,
                        "url": f"https://github.com/{options.owner}/{options.repository}/pull/{pr_id}",
                    }
                changes["all"].append(change)
                changes[section].append(change)
        return changes

    tags = list(github_get_paginated(f"https://api.github.com/repos/{options.owner}/{options.repository}/tags", params={
        "per_page": 100,
    }))

    def get_tag_sha(name):
        for tag in tags:
            if tag["name"] == name:
                return tag["commit"]["sha"]
        raise KeyError(name)

    results = []
    releases = github_get_paginated(f"https://api.github.com/repos/{options.owner}/{options.repository}/releases", params={
        "per_page": 100,
    })
    for release in releases:
        changes = parse_changes(release)

        manifest_assets = [asset for asset in [asset for asset in release["assets"] if asset["name"] == "manifest.json"] if asset is not None]
        if manifest_assets:
            # Use the manifest if it exists.
            manifest = github_get(manifest_assets[0]["browser_download_url"]).json()
        else:
            # Synthesizing a manifest from the listed releases.

            # Look up the git sha of the release tag.
            git_sha = get_tag_sha(release["tag_name"])

            # Parse the artifacts augmenting them were possible.
            artifacts = [extract_artifact(asset, git_sha) for asset in release["assets"]]
            artifacts = list(filter(lambda x: x is not None, artifacts))

            # Get the version and build number if they're consistent (or absent) across all detected assets.
            extracted_metadata = extract_keys(artifacts, ["version", "build_number"])

            # Synthesize a version and build number from the release if we weren't able to detect one.
            if not extracted_metadata:
                extracted_metadata = {
                    "version": release["name"],
                    "build_number": 0,
                }

            # Synthesize the manifest.
            manifest = {
                "version": 1,
                "metadata": {
                    "version": extracted_metadata["version"],
                    "build_number": extracted_metadata["build_number"],
                    "git_sha": git_sha,
                },
                "artifacts": artifacts,
            }

        # Bind the release information into the manifest.
        manifest = augment_manifest(manifest, release)

        results.append(manifest)

    # Flatten the artifacts' supports lists.
    flat_releases = [
        {
            **release,
            "artifacts": [
                {**{k: v for k, v in artifact.items() if k != "supports"}, "support": support}
                for artifact in release["artifacts"]
                for support in artifact["supports"]
            ],
        }
        for release in results
    ]

    print(json.dumps(flat_releases, indent=4, ensure_ascii=False))


@dataclass
class Build:
    number: int
    sha_short: str
    date: datetime


def parse_build_number(build_number):
    date_string, sha_string = build_number[:10], build_number[10:]
    date = datetime.datetime.strptime(date_string, "%y%m%d%H%M")
    sha_short = "%06x" % int(sha_string)

    return Build(number=build_number, sha_short=sha_short, date=date)


@fastcommand.command("parse-build-number", help="parse a build nunmber to retrieve the date and Git SHA", arguments=[
    fastcommand.Argument("build", help="build number to parse")
])
def command_synthesize_build_number(options):
    date_string, sha_string = options.build[:10], options.build[10:]
    date = datetime.datetime.strptime(date_string, "%y%m%d%H%M")
    sha = "%06x" % int(sha_string)
    print("%s (UTC)" % date)
    print(sha)


@fastcommand.command("import-base64-certificate", help="import base64 encoded certificate to a specific keychain", arguments=[
    fastcommand.Argument("path", help="path of the keychain to update"),
    fastcommand.Argument("certificate", help="base64 encoded PKCS12 (.p12) certificate"),
    fastcommand.Argument("--password", "-p", action="store_true", default=False, help="read password from stdin"),
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


@fastcommand.command("install-provisioning-profile", help="install provisioining profile for the current user", arguments=[
    fastcommand.Argument("path", nargs="+", help="path of profile to install"),
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


@fastcommand.command("init-manifest", help="create a new artifact manifest", arguments=[

    fastcommand.Argument("manifest", help="manifest to create or update"),

    fastcommand.Argument("--version", required=True, help="version of the project"),
    fastcommand.Argument("--build-number", required=True, help="build number of the project"),

    fastcommand.Argument("--git-sha", help="git sha of the project"),
])
def command_init_manifest(options):
    manifest_path = os.path.abspath(options.manifest)

    manifest = {
        "version": 2,
        "metadata": {
            "version": options.version,
            "build_number": options.build_number,
        },
        "artifacts": [],
    }
    if options.git_sha is not None:
        manifest["metadata"]["git_sha"] = options.git_sha

    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=4)
        fh.write("\n")


@fastcommand.command("add-artifact", help="add an artifact to the artifact manifest", arguments=[

    fastcommand.Argument("manifest", help="manifest to create or update"),

    fastcommand.Argument("--project", required=True, help="id of the project to add; should be consistent across all artifacts for a specific project"),
    fastcommand.Argument("--version", required=True, help="version of the project"),
    fastcommand.Argument("--build-number", required=True, help="build number of the project"),

    fastcommand.Argument("--name", help="filename of the asset; inferred from the path if not provided"),
    fastcommand.Argument("--path", required=True, help="path to the artifact (relative or absolute); in the case of GitHub releases this should be the assset filename"),
    fastcommand.Argument("--format", required=True, choices=["deb", "pkg", "uf2", "zip"], help="artifact format"),
    fastcommand.Argument("--git-sha", required=True, help="git sha associated with the artifact"),

    fastcommand.Argument("--supports-os", required=True, choices=["macos", "debian", "ubuntu", "zmk"], help="supported os"),
    fastcommand.Argument("--supports-version", required=True, help="supported os version (e.g., 26, 24.04, etc)"),
    fastcommand.Argument("--supports-codename", required=True, help="supported os codename (e.g., tahoe, noble, etc); repeat the os version if not relevant"),
    fastcommand.Argument("--supports-architecture", required=True, choices=["arm64", "aarch64", "x86_64", "amd64", "nice-nano-v1", "nice-nano-v2"], action="append", default=[], help="supported os architecture (specify one-or-more)"),
])
def command_add_artifact(options):
    manifest_path = os.path.abspath(options.manifest)
    artifact_path = os.path.abspath(options.path)

    # Load any existing manifest.
    manifest = {
        "version": 1,
        "artifacts": [],
    }
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as fh:
            manifest = json.load(fh)

    if "version" not in manifest or manifest["version"] not in set([1, 2]):
        exit("Unsupported manifest version.")

    name = options.name if options.name else os.path.basename(options.path)

    sha256 = shasum(artifact_path)

    supports = []
    for architecture in options.supports_architecture:
        supports.append({
            "os": options.supports_os,
            "version": options.supports_version,
            "codename": options.supports_codename,
            "architecture": architecture,
        })

    # Look for an existing artifact to update with additional target information.
    found_artifact = False
    for artifact in manifest["artifacts"]:
        if (artifact["project"] == options.project and
            artifact["version"] == options.version and
            artifact["build_number"] == options.build_number and
            artifact["sha256"] == sha256 and
            artifact["name"] == name and
            artifact["path"] == options.path and
            artifact["format"] == options.format and
            artifact["git_sha"] == options.git_sha):

            artifact["supports"].extend(supports)
            found_artifact = True
            break

    # If we weren't able to find an artifact to update, then we create a new one.
    if not found_artifact:
        manifest["artifacts"].append({
            "project": options.project,
            "version": options.version,
            "build_number": options.build_number,

            "sha256": sha256,
            "name": name,
            "path": options.path,
            "format": options.format,
            "git_sha": options.git_sha,

            "supports": supports,
        })

    # Write the updated manifest.
    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=4)
        fh.write("\n")


def main():
    parser = fastcommand.CommandParser(description="Create and register a temporary keychain for development")
    parser.run()


if __name__ == "__main__":
    main()
