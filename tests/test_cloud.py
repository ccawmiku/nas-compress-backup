from types import SimpleNamespace

import pytest

from app import cloud as cloud_module
from app import core
from app.cloud import Cloud, CloudError


class FakeStub:
    def __init__(self, channel):
        self.channel = channel


def _fake_import(pb, rpc):
    def load(name, package=None):
        return pb if name.endswith('clouddrive_pb2') else rpc
    return load


def test_cloud_reports_missing_generated_bindings(state, monkeypatch):
    core.update_settings({'cloud_url': 'http://127.0.0.1:19798'})

    def missing_import(name, package=None):
        raise ImportError(f'no generated module {name}')

    monkeypatch.setattr(cloud_module, 'import_module', missing_import)
    with pytest.raises(CloudError, match='protobuf bindings are missing'):
        Cloud()


def test_cloud_constructs_when_generated_bindings_exist(state, monkeypatch):
    core.update_settings({'cloud_url': 'http://127.0.0.1:19798'})
    pb = SimpleNamespace(ListSubFileRequest=SimpleNamespace)
    rpc = SimpleNamespace(CloudDriveFileSrvStub=FakeStub)

    monkeypatch.setattr(cloud_module, 'import_module', _fake_import(pb, rpc))
    cloud = Cloud()
    try:
        assert cloud.pb is pb
        assert cloud.rpc is rpc
        assert isinstance(cloud.stub, FakeStub)
        assert cloud.stub.channel is cloud.channel
    finally:
        cloud.close()
