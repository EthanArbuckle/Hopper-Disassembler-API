import json
import logging
import subprocess
import time
from http import server
from pathlib import Path

import requests

from hopper_proxy import TerminateHopper

logger = logging.getLogger("hopper_launch")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s:   %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

TerminateHopper.kill_hopper()

hopper_launcher_path = "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper"
hopper_path = "/Applications/Hopper Disassembler v4.app/Contents/MacOS/Hopper Disassembler v4"


def server_list_documents(port):
    endpoint = f"http://localhost:{port}/documents"
    response = requests.get(endpoint)
    return response.json().get("data")


def server_get_doc_filepath(port, document_name):
    endpoint = f"http://localhost:{port}/filepath"
    try:
        response = requests.post(endpoint, data=json.dumps({"document_name": document_name}))
        return response.json().get("data")
    except Exception as e:
        print(e)
    return None


def _launch_binary_workaround_hopper_bug(binary: Path, command_args):
    # Launch Hopper with a test binary and the proxy script
    # Work around the "missing loader" bug
    for _ in range(2):
        try:
            subprocess.check_output([hopper_launcher_path, "-A", "-e", binary.as_posix()] + command_args, stderr=subprocess.STDOUT)
            break
        except subprocess.CalledProcessError as e:
            if e.stdout and b"The handler some object is not defined." in e.stdout:
                # Workaround the bug
                try:
                    subprocess.check_output([hopper_launcher_path], stderr=subprocess.STDOUT)
                except:
                    pass
                time.sleep(1)
            else:
                print(e.stdout)
                raise


def _is_binary_fat(binary: Path):
    """Is this a FAT macho"""
    # Use lipo to determine if the file is FAT
    return b"the fat file" in subprocess.check_output(["/usr/bin/lipo", "-info", binary.as_posix()])


def launch_server():
    """Launch Hopper with a dummy document and start a proxy server."""
    # Small dummy binary (TODO: use smaller binary)
    dummy_document = Path("lzssdec").resolve()
    hopper_args = [
        "-l",
        "Mach-O",
        "--intel-64",
    ]
    # Launch the hopper server. This server will handle requests for any subsequent Documents that are opened.
    # This is basically idempotent - repeat launches will silently fail to bind the server port
    _launch_binary_workaround_hopper_bug(dummy_document, hopper_args)
    
    
def find_hopper_server_port():
    """ Find the port that Hopper's server is running on
    """
    try:
        hopper_launch_output = subprocess.check_output([hopper_path], stderr=subprocess.STDOUT)
        port = hopper_launch_output.split(b"Hopper already running on port: ")[1]
        return int(port)
    except:
        pass
    return None


def open_binary_in_hopper(binary: Path, arch_flag):
    """Launch a binary in Hopper. (No server is started)"""
    hopper_args = [
        "-l",
        "Mach-O",
        arch_flag,
    ]
    if _is_binary_fat(binary):
        # If its FAT, add the correct loader flag
        hopper_args += ["-l", "FAT"]
    _launch_binary_workaround_hopper_bug(binary, hopper_args)


def wait_for_document(port, document_name):
    """Wait for a specific Document to become available"""
    while True:
        try:
            documents = server_list_documents(port)
            if document_name in documents:
                break
        except requests.exceptions.ConnectionError:
            pass


def wait_for_new_document(port, previous_docs):
    """Wait for a previously-unknown Document to become available.
    previous_docs: Document names that are already known
    """
    while True:
        try:
            new_documents = server_list_documents(port)
            if len(new_documents) > len(previous_docs):
                # Find the new item
                new_document = [new_doc for new_doc in new_documents if new_doc not in previous_docs][0]
                return new_document
        except requests.exceptions.ConnectionError:
            pass


def wait_for_named_document_with_path(port, document_file_path):
    """Wait for a Document to become available that:
    1. Has a real name, which indicates it is not still processing
    2. Has a executablePath that matches the provided document_file_path
    """
    while True:
        try:
            new_documents = server_list_documents(port)
            for document in new_documents:
                # Skip un-named (still analyzing) docs
                if "Untitle" in document:
                    continue
                if document_file_path == server_get_doc_filepath(port, document):
                    return document

            time.sleep(1)

        except requests.exceptions.ConnectionError:
            pass


testbin_path = Path("/Users/ethanarbuckle/Desktop/decrypt")#Path("/Users/ethanarbuckle/Downloads/app_downloads/Payload 65/app-decrypt-com.cvs.cvspharmacyr1buo3ck.app/CVSOnlineiPhone")
# Launch a dummy document. It will host the server that handles responses for *all* documents
launch_server()

# Find the port the server is hosting on
server_port = find_hopper_server_port()
if not server_port:
    print("failed to find server port!")
    exit(0)

# Wait for the server to launch
wait_for_document(server_port, "lzssdec.hop")
logger.info(f"server launched on port {server_port}")

# Note the names of the current Hopper documents
current_hopper_docs = server_list_documents(server_port)

# Open the requested document.
arch_flags = "--aarch64"
open_binary_in_hopper(testbin_path, arch_flags)

# Wait for the server to acknowledge the new document
# new_doc_name = testbin_path.name + ".hop"
document_name = wait_for_new_document(server_port, current_hopper_docs)
logger.info(f"found new document: {document_name}")
if "Untitle" in document_name:
    logger.info("waiting for initial analysis to finish...")
    # Wait for a named document to become available
    document_name = wait_for_named_document_with_path(server_port, testbin_path.as_posix())

logger.info(f"document ready: {document_name}")
