"""Fetch the official, pinned CloudDrive2 API definition at build time."""
import hashlib
import importlib.resources
import urllib.request
from pathlib import Path

from grpc_tools import protoc

URL = 'https://www.clouddrive2.com/api/clouddrive.proto'
TARGET = Path(__file__).resolve().parents[1] / 'app/vendor'
TARGET.mkdir(parents=True, exist_ok=True)
data = urllib.request.urlopen(URL, timeout=60).read()
EXPECTED_SHA256 = '838ebe12b7203510bc1749422a11a2f1c9d02dd9287503250074786f8b06b69b'
if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
    raise SystemExit('CloudDrive2 API definition changed; review and update the pinned checksum before building.')
# The API is a build-time dependency, never a source of runtime credentials.
proto = TARGET / 'clouddrive.proto'
proto.write_bytes(data)
include = str(importlib.resources.files('grpc_tools') / '_proto')
result = protoc.main(['protoc', '-I' + str(TARGET), '-I' + include,
                     '--python_out=' + str(TARGET), '--grpc_python_out=' + str(TARGET), str(proto)])
if result:
    raise SystemExit(result)
binding = TARGET / 'clouddrive_pb2_grpc.py'
binding.write_text(binding.read_text(encoding='utf-8').replace('import clouddrive_pb2 as', 'from . import clouddrive_pb2 as'), encoding='utf-8')
print('Generated CloudDrive2 bindings; API definition SHA256:', hashlib.sha256(data).hexdigest())
