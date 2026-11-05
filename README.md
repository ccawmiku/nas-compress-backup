# NAS Compress Backup

在 NAS 上按任务分批加密归档，通过 CloudDrive2 直接上传百度网盘。React、Lucide React 和 daisyUI 界面，Python/FastAPI 与 SQLite 后端。

## 功能

- 多个独立任务，目录选择器可浏览只读接入的 `/volume1` 和 `/volume2`。
- 创建任务后先扫描，展示新增、修改、移动、源已删除和小文本逐行差异，由用户开始首次备份。
- 每晚检查增量；夜间时段在设置里填写。到点不开始新包，允许当前工作和已开始的上传收尾。手动运行可绕过时段。
- 工作数据默认上限128GB，按恢复组预留空间，不先压完整个来源目录；大文件有界分段。
- 按后缀选择压缩级别，7z内容及文件名加密。每个上传对象不超过3,900,000,000字节。
- 外置PAR2保护数据包与加密组清单，恢复块按最大成员计算；组内其他文件和冗余完好时，可恢复一个完整缺失成员。
- 逐包上传；任务完成、云端数量与大小匹配后，更新当前索引并回收本地工作副本。
- 一个路径只维护当前成功副本。NAS上删除源文件时，保留网盘副本；不提供备份点或历史版本。
- Bark只提醒重试耗尽等需要处理的异常，同类异常24小时内去重。正常完成不推送。

**上传确认只比较数量和字节数，不会下载回读，也不等于远端内容的SHA-256验证。** 本地仍计算文件哈希、检查压缩包和PAR2。

## 安装

目前提供 Linux amd64 镜像，适合 x86-64 群晖。镜像由本仓库 GitHub Actions 测试、构建并发布：

```text
ghcr.io/ccawmiku/nas-compress-backup:latest
```

1. 先运行官方 CloudDrive2 并连接百度网盘。将 `/volume1/暂时上传` 映射到 CloudDrive2 的 `/upload:ro`。
2. 下载本仓库 `compose.yaml`，按实际卷位置修改状态/工作目录。
3. 创建来源挂载、数据和工作目录后，在 Container Manager 导入项目启动。
4. 在局域网打开 `http://NAS-IP:19880`，创建自己的管理员账号。
5. 设置 CloudDrive2 地址和API令牌，点击“保存并测试连接”；设置归档密码、Bark和夜间时段。
6. 新建任务，查看扫描结果后点击“立即运行”。默认云端总目录“群晖压缩备份”。

配置和令牌保存在持久化数据目录，API不返回明文令牌或密码。真实凭据不要写入Compose或提交Git。可选的私有引导文件格式如下，放在仓库外并以只读方式挂载到 `/run/secrets/bootstrap.json`：

```json
{
  "clouddrive_token": "YOUR_PRIVATE_API_TOKEN",
  "archive_password": "YOUR_ARCHIVE_PASSWORD",
  "bark_url": "YOUR_PRIVATE_BARK_URL"
}
```

引导文件只补充尚未配置的值，不覆盖现有设置。首次备份前可以设置归档密码；有归档后第一版锁定密码，避免已有数据无法解密。

## 存储结构

```text
群晖压缩备份/
  任务名称_固定ID/
    groups/组ID/       数据包、加密文件清单、PAR2和提交记录
    catalog-a/         当前索引的两个交替写入槽之一
    catalog-b/         用于中断时保留一个可读索引
```

两个索引槽用于提交中断后的对账，不作为用户历史版本功能。选择有效且代次最高的目录，解密 `current-index.7z` 得到 `current-index.json`；它包含原始路径、包内路径、分段顺序和SHA-256。来源删除后保留的条目会标记 `present: 0`。

多文件共享压缩包，多个包共享PAR2。组内还有当前有效内容时保留整组，混合包中的过时字节不会为了整理而自动重压；因此取消历史功能也不意味着每次修改都会立即释放旧包的全部空间。

临时空间配额覆盖本程序数据工作区，数据库/日志另计；现有CloudDrive2自己的缓存由CloudDrive2配置控制。系统余量不足时等待。源文件持续变化会暂缓处理；应用数据库等活跃数据需要合适的一致性备份方式。

## 取回当前文件

网页“备份文件 → 查看位置”可查看和下载所需数据包及PAR2。缺失包先在其组目录运行 `par2 repair recovery.par2`。

下载对应任务的索引和数据组，解密索引后可使用附带工具按分段重建一个文件：

```bash
python scripts/restore_file.py \
  --index /path/to/current-index.json \
  --archives /path/to/downloaded-task-directory \
  --path '/original/source/file.mp4' \
  --output /path/to/new-destination/file.mp4 \
  --password-file /path/to/private-password-file
```

工具不会覆盖已存在的目标文件；完成后检查分段和整文件SHA-256。无需原NAS数据库，也不需要管理网页在线。

## 开发和测试

Python 3.12+、Node.js 24，以及 `7zz`、`par2`。

```bash
pip install -r requirements.txt
python scripts/generate_proto.py
pytest -q
cd frontend
npm ci
npm run build
```

前端开发使用 `npm run dev`；后端使用 `uvicorn app.main:app --host 127.0.0.1 --port 19880`。设置 `NCB_DATA`、`NCB_WORK`、`NCB_OUT` 和 `NCB_ROOTS` 指向隔离测试目录。

GitHub Actions 在 Linux 上运行真实分段归档、增量更新和完整缺失对象PAR2修复测试，通过后构建并推送镜像。7-Zip二进制与CloudDrive2 API定义都校验固定SHA-256；官方API定义变更时应人工核对并更新固定值。

管理员密码遗忘时，在NAS本机执行 `docker exec nas-compress-backup python -m app.admin reset`，随后在内网页面重新创建账号。此操作保留任务和归档数据。

