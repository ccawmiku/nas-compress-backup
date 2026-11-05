from __future__ import annotations

import re
import threading
from urllib.parse import urlsplit

import grpc
from google.protobuf.empty_pb2 import Empty

from . import core
from .vendor import clouddrive_pb2 as pb
from .vendor import clouddrive_pb2_grpc as rpc


class CloudError(RuntimeError):
    pass


def component(value: str) -> str:
    result = re.sub(r'[\\/\x00-\x1f]', '_', value).strip('. ')
    if not result or result in ('.', '..'):
        raise ValueError('无效的文件夹名称')
    return result[:80]


class Cloud:
    def __init__(self):
        config = core.settings()
        parsed = urlsplit(config['cloud_url'])
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise CloudError('CloudDrive2 地址无效')
        target = parsed.netloc
        self.base_url = config['cloud_url'].rstrip('/')
        self.token = core.get_secrets().get('clouddrive_token', '')
        if not self.token:
            raise CloudError('请先在设置中配置 CloudDrive2 API 令牌')
        self.channel = (grpc.secure_channel(target, grpc.ssl_channel_credentials()) if parsed.scheme == 'https'
                        else grpc.insecure_channel(target))
        self.stub = rpc.CloudDriveFileSrvStub(self.channel)
        self.metadata = (('authorization', 'Bearer ' + self.token),)

    def close(self):
        self.channel.close()

    def call(self, method, request=None, timeout=45):
        try:
            return getattr(self.stub, method)(request or Empty(), metadata=self.metadata, timeout=timeout)
        except grpc.RpcError as error:
            labels = {'UNAUTHENTICATED': '令牌无效或已过期', 'PERMISSION_DENIED': '令牌权限不足',
                      'UNAVAILABLE': '服务无法连接', 'DEADLINE_EXCEEDED': '请求超时'}
            code = error.code().name
            raise CloudError('CloudDrive2：' + labels.get(code, code)) from None

    def files(self, path: str, refresh=False) -> list:
        result = []
        try:
            for reply in self.call('GetSubFiles', pb.ListSubFileRequest(path=path, forceRefresh=refresh), timeout=90):
                result.extend(reply.subFiles)
        except grpc.RpcError as error:
            raise CloudError('无法读取云端目录：' + error.code().name) from None
        return result

    def test(self) -> dict:
        system = self.call('GetSystemInfo')
        if not system.IsLogin or not system.SystemReady:
            raise CloudError('请先在 CloudDrive2 网页登录账号')
        roots = self.files('/', True)
        baidu = [{'name': f.name, 'path': f.fullPathName} for f in roots if f.CloudAPI.name == '百度网盘']
        if not baidu:
            raise CloudError('CloudDrive2 中尚未连接百度网盘')
        local = next((f for f in roots if f.isLocal and
                      (f.originalPath.rstrip('/') == '/upload' or f.name in ('NAS待上传', 'NAS压缩备份'))), None)
        if local is None:
            login = self.call('APIAddLocalFolder', pb.AddLocalFolderRequest(
                localFolderPath='/upload', displayName='NAS压缩备份'))
            if not login.success:
                raise CloudError('添加待上传目录失败：' + core.redact(login.errorMessage))
            local = next((f for f in self.files('/', True) if f.isLocal and f.name == 'NAS压缩备份'), None)
        if not local:
            raise CloudError('未找到 CloudDrive2 本地待上传目录')
        config = core.settings()
        root = config['cloud_root'] if config['cloud_root'] in [b['path'] for b in baidu] else baidu[0]['path']
        core.update_settings({'local_source': local.fullPathName, 'cloud_root': root})
        return {'connected': True, 'baidu_roots': baidu, 'local_source': local.fullPathName}

    def ensure_folder(self, parent: str, name: str) -> str:
        name = component(name)
        existing = next((f for f in self.files(parent, True) if f.name == name), None)
        if existing:
            if not existing.isDirectory:
                raise CloudError('目标文件夹名称已被文件占用')
            return existing.fullPathName
        result = self.call('CreateFolder', pb.CreateFolderRequest(parentPath=parent, folderName=name), timeout=90)
        if not result.result.success:
            raise CloudError('创建云端文件夹失败：' + core.redact(result.result.errorMessage))
        return result.folderCreated.fullPathName

    def task_destination(self, task: dict) -> str:
        if task.get('cloud_dest'):
            return task['cloud_dest']
        config = core.settings()
        if not config['cloud_root'] or not config['local_source']:
            self.test()
            config = core.settings()
        base = self.ensure_folder(config['cloud_root'], config['cloud_base'])
        dest = self.ensure_folder(base, component(task['name']) + '_' + task['id'][:8])
        core.execute('UPDATE tasks SET cloud_dest=? WHERE id=?', (dest, task['id']))
        return dest

    def start_copy(self, source: str, destination: str, overwrite=False):
        result = self.call('CopyFile', pb.CopyFileRequest(
            theFilePaths=[source], destPath=destination,
            conflictPolicy=pb.CopyFileRequest.Overwrite if overwrite else pb.CopyFileRequest.Skip), timeout=90)
        if not result.success:
            raise CloudError('提交上传失败：' + core.redact(result.errorMessage))

    def uploads(self, destination: str) -> dict:
        result = self.call('GetUploadFileList', pb.GetUploadFileListRequest(
            getAll=True, filter=destination, itemsPerPage=500, pageNumber=1))
        # Avoid dependence on a generated field spelling across CloudDrive2 releases.
        entries = []
        for field in result.DESCRIPTOR.fields:
            if field.is_repeated and field.message_type:
                entries = list(getattr(result, field.name))
                break
        return {f.destPath: {'bytes': int(f.transferedBytes), 'status': int(f.statusEnum),
                             'error': core.redact(f.errorMessage)} for f in entries
                if f.destPath.startswith(destination.rstrip('/') + '/')}

    def copy_tasks(self):
        return self.call('GetCopyTasks').copyTasks

    def delete_owned_group(self, path: str, task_dest: str):
        if not path.startswith(task_dest.rstrip('/') + '/groups/'):
            raise CloudError('拒绝删除任务仓库之外的目录')
        result = self.call('DeleteFile', pb.FileRequest(path=path))
        if not result.success:
            raise CloudError('清理无用组失败：' + core.redact(result.errorMessage))

    def download_info(self, path: str):
        return self.call('GetDownloadUrlPath', pb.GetDownloadUrlPathRequest(
            path=path, preview=False, lazy_read=False, get_direct_url=False))
