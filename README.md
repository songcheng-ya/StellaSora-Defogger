# StellaSora-Defogger
这是一个给星塔旅人（国服）去除遮挡角色的白雾的脚本，适用于安卓端和windows端

具体的使用方式在对应压缩包的txt文件，安卓端去白雾需要windows电脑配合（可能会有不需要电脑的版本？挖个坑）

# 星塔旅人（StellaSora CN）去白雾工具技术细节说明（README）

本文档整理了《星塔旅人》国服 **PC 端** 与 **Android 安卓端** 去白雾自动化工具集的逆向分析结论、二进制修补算法、静态图集去雾数学模型、零编译器原生代理 DLL 生成细节及跨平台工程实现。
具体技术细节完全由ai编写，作者本人并不具备对应的专业知识

> **核心原则**：所有去白雾操作均通过**直接修补磁盘 AssetBundle 文件**实现，不在游戏进程中注入内存渲染 Hook；PC 端可选的 `version.dll` 代理仅用于无感拉起后台资源监听进程。

---

## 1. 系统整体架构与文件说明

| 模块 | 职责说明 |
| --- | --- |
| `auto_defog.py` | 核心检测与修补引擎（PC 目录探测、`CubismCore` `.moc3` 解析/修补、Prefab `MeshRenderer` 禁用、静态 2D `SpriteAtlas` 渲染反推去雾、原子写回、原版备份与进程 PID 守护） |
| `tools/build_proxy_dll.py` | 纯 Python 编写的 PE32+ x64 `version.dll` 代理生成器（零 C/C++ 编译器依赖） |
| `android_defog.py` | 安卓端适配器（MTP / ADB / 本地目录三种传输后端、只读增量元信息比对、SHA-256 去重修补、ZIP / ADB / Shizuku 交付包生成与交互菜单 `--menu`） |
| `tools/build_portable_release.py` | 独立便携版构建器（基于 `python312._pth` 隔离精简版 CPython 3.12 运行时，构建整合包与 PC/Android 分离目录） |

---

## 2. Live2D（`.moc3`）白雾识别与二进制修补

### 2.1 资源过滤与路径门控
游戏内所有资源按以下三个 Store 扫描：
- PC 端：`Patch_Store\AssetBundles`、`Persistent_Store\AssetBundles`、`xtlr_Data\StreamingAssets\InstallResource`
- 安卓端：`/sdcard/Android/data/com.RoamingStar.StellaSora/files/{Patch_Store,Persistent_Store,Temporary_Store}/AssetBundles`

候选筛选规则 `_is_l2d_candidate(store_tag, fname)`：
- 仅处理 `.unity3d` 文件；
- 排除 `char_2d_*` 与 `char_avg_2d_*`（避免 Pass 1 将静态 2D 包误标为 `clean` 导致 Pass 2 跳过）；
- 满足文件名含 `_l2d` 或位于 `patch` store。

在 `find_fog_drawables()` 中强制要求容器路径包含 `"/cen/"`：
- 实测非和谐版路径 `/noncen/` 存在白色光环、刘海高光、烟花特效等正常美术网格（例如 `char_l2d_11501` 的 `guang_1`、`14103` 的 `rabbit_soul`、`14301` 的 `lian7`、`14501` 的 `liuhai*`、`disc_l2d_4005` 的 `ArtMesh0`、`4017` 的 `L_fireworks_ball`）；
- `/cen/` 门控可完全杜绝非和谐资源的误判。

### 2.2 双层白雾网格（Drawable）检测策略
通过 `ctypes` 调用 `Live2DCubismCore.dll`（`find_core_dll()` 依次查找配置目录、`PROJECT_DIR\Live2DCubismCore.dll`、`runtime\Live2DCubismCore.dll` 与自动探测的 PC 客户端目录），使用 64 字节对齐内存缓冲区执行 `csmReviveMocInPlace` → `csmInitializeModelInPlace` → `csmUpdateModel`，遍历全部 Drawable：

1. **前置跳过**：
   - 无顶点、透明度 `opacity <= 0.05`（已隐藏）或退化网格 `len(set(verts)) <= 1`；
   - 匹配 `NAME_OTHER_HIDE`（`hexie|cover|zhedang|oppaicover|white_clothes|legcover|hexieban|mask|qipao`）的遮挡衣物部件。
2. **第一层（命名精确匹配 `named_fog`）**：
   - 正则 `NAME_FOG = r"^(hi|HI|Hi|hi_\d+|shengguang|shengguang_\d+|guang_\d+|whitefog|fog_\d+)$"`。
3. **第二层（视觉/几何特征匹配 `soft_white`）**：
   - 排除人体/服饰部件名 `NAME_PART`；
   - 模型空间跨度 `span = max(max(x)-min(x), max(y)-min(y)) >= 1.0`；
   - 提取 UV 包围盒对应的原贴图区域（`_tex_stats`，若面积超过 `256x256` 则缩放采样，`alpha > 10`）：
     - 高白像素比例 `white_frac`（`R,G,B > 225`）`>= 0.6`；
     - 浅色像素比例 `pale_frac`（`min(R,G,B) > 195`）`>= 0.9`；
     - 平均不透明度 `15 <= avg_alpha <= 235`。

### 2.3 `.moc3` 二进制原地修改与 Unity Prefab 联动
`patch_moc3_bytes(moc_bytes, fog_idxs)` 直接解析 Live2D `.moc3` 二进制段表（校验魔数 `b"MOC3"`）：
- 偏移 `64` 处读取 `<160I` 段偏移表 `secs[]`；
- 从 `secs[0]` 读取 `<16I` `CountInfo`（`n_am = ci[4]` 为 ArtMesh 数量，`n_akf = ci[9]` 为 Keyform 数量）；
- 读取关键数组偏移：
  - ArtMesh Keyform 起始/数量表：`secs[35]`（`am_kfb`）、`secs[36]`（`am_kfc`）
  - ArtMesh 顶点数与 UV 起始偏移：`secs[43]`（`am_vcnt`）、`secs[44]`（`am_uvbeg`）
  - Keyform 透明度表与顶点偏移表：`secs[68]`（`akf_op_off`）、`secs[70]`（`akf_vpb`）
  - 顶点坐标区 `secs[71]`（`vp_off`）、UV 区 `secs[78]`（`uv_off`）
- 对命中的每个索引 `i`：
  1. 将 UV 缓冲区 `uv_off + (uv0 + v) * 4` 处的 `vc * 2` 个 `float32` 置为 `0.0`；
  2. 对其所有关键帧 `k ∈ [beg, beg + cnt)`，将透明度 `akf_op_off + k * 4` 及顶点位置 `vp_off + (vpb + v) * 4`（共 `vc * 2` 个 `float32`）全部写为 `0.0`。
- 写回后立即调用 `csmHasMocConsistency()` 验证二进制结构一致性，并二次实例化 `CubismModel` 验证所有命中网格均满足 `opacity <= 0.001` 且顶点已坍缩。
- `_disable_fog_mesh_renderers()` 同步扫描 Bundle 内 `GameObject`，仅对名称在 `fog_names` 中且挂载了匹配 `Cubism` `MonoBehaviour` 的节点关闭其 `MeshRenderer.m_Enabled = False`。

---

## 3. 静态 2D 立绘（`SpriteAtlas`）白雾逆向剥离

部分角色（如 `char_2d_14902.unity3d`）在静态 2D `SpriteAtlas` 中直接烘焙了与 Live2D `_l` 模型相同位置和形态的白雾像素。`restore_static_2d_bundle()` 基于同角色的**未去雾原版 `<id>_l` `.moc3`** 进行精确反推剥离：

1. **图集坐标映射**：
   - 定位 `<id>_001.png` 对应 `Sprite` 及其关联的 `m_SpriteAtlas` → `m_RenderDataMap` 项；
   - 由 `textureRect (rx, ry, rw, rh)`、`textureRectOffset (ox, oy)`、`m_Rect (sp_w, sp_h)` 与 `m_PixelsToUnits (sp_ppu)` 计算模型原点在图集像素坐标中的精确位置：
     - `org_x = round(rx) - round(ox) + sp_w / 2.0`
     - `org_y = th - round(ry) - sp_h + round(oy) + sp_h / 2.0`
   - 按白雾 Drawable 顶点包围盒外扩 `pad = 0.35` Cubism 单位裁剪目标像素区域 `(px0, py0, px1, py1)`。
2. **软光栅渲染与存在性校验（`_static_fog_matches`）**：
   - 使用自研软件光栅渲染器 `render_model()`（支持 `render_order` 排序、正常混合、加法混合 `cflag & 0x01` 与乘法混合 `cflag & 0x02`、以及 `multiply` 乘色）；
   - 在深色背景 `(18, 22, 32, 255)` 下分别渲染含雾 `ref_on` 与去雾 `ref_off`，提取差异像素掩码（`|ΔRGB| > 45` 且 `n_mask >= 150`）；
   - 仅当原图更接近 `ref_on` 而明显偏离 `ref_off`（`d_on < d_off * 0.65 and d_off > 12.0`）时才判定存在烘焙白雾，防止误伤原本无雾或与 Live2D 构图不一致的静态立绘。
3. **2× 超采样 α-Matting 剥离重建**：
   - 以 `ss = 2`（`2×` 超采样 + `Image.LANCZOS` 下采样）分别在纯黑 `(0,0,0,255)` 与纯白 `(255,255,255,255)` 背景下渲染无雾人物（`blk`, `wht`）与纯白雾层（`fog_blk`, `fog_wht`）；
   - 由白/黑背景响应差还原白雾遮罩不透明度 `fa` 与无雾人物不透明度 `alpha`：
     - 仅在 `fa >= 0.01` 的像素处剥离纯白前向叠加雾层：
       `b_c = clamp((orig_c - 255 * fa) / max(0.12, 1.0 - fa), 0, 255)`
     - 再将预乘分离得到的人物前景颜色 `(cr, cg, cb)` 与还原背景 `b` 重新混合，未受白雾影响区域保留原图集像素不变。

---

## 4. 原子写回与文件句柄安全（`atomic_save_bundle`）

`UnityPy.load()` 在读取较大 Bundle 时可能会保持底层文件流打开状态，直接 `os.replace()` 在 Windows 上易触发 `PermissionError (WinError 5)`。因此 `atomic_save_bundle()` 采用：
1. 先调用 `env.save(pack="original", out_path=tmp_dir)` 输出到暂存目录；
2. 显式遍历 `env.files.values()` 关闭 `reader.stream`，`del env` 后执行 `gc.collect()` 释放句柄；
3. 复制为目标同目录下的 `.defog_tmp` 临时文件后通过 `os.replace` 原子替换，遇 `PermissionError` 最多重试 6 次（`0.1s` 退避），最后保留 `shutil.copyfileobj` 回退写入。

---

## 5. PC 端零编译器原生 x64 `version.dll` 代理

`tools/build_proxy_dll.py` 不依赖 MSVC / MinGW，直接使用内置双遍 RIP 相对寻址汇编器 `Asm` 输出完整可用的 **4,608 字节** PE32+ x64 DLL（`.text` + `.rdata` + `.data`）：

1. **透明转发层**：
   - 按字母序构造标准 PE Export Directory，导出 Windows `version.dll` 全部 17 个函数（`GetFileVersionInfo*`、`VerFindFile*`、`VerInstallFile*`、`VerLanguageName*`、`VerQueryValue*`）；
   - 每个导出桩函数调用惰性初始化例程 `InitRealVersionDll()`：通过 `lock cmpxchg` 原子状态机控制并发，首次调用时通过 `GetSystemDirectoryW` + `LoadLibraryW` 加载系统 `%SystemRoot%\System32\version.dll`，并以 `GetProcAddress` 解析目标地址后 `jmp [rip+slot]` 尾调用转发，规避 Windows `LoaderLock` 限制。
2. **后台监听拉起**：
   - `DllMain(DLL_PROCESS_ATTACH)` 调用 `DisableThreadLibraryCalls` 后直接 `CreateThread` 启动 `WorkerProc` 并立即返回；
   - `WorkerProc` 在 `CreateProcessW` 中以 `CREATE_NO_WINDOW (0x08000000)` 启动：
     `"<pythonw.exe>" "<auto_defog.py>" --watch-pid <xtlr_pid>`
   - 命令行缓冲区预先校验 `len(cmd_prefix) + 16 <= (0x500 - 0xD0) // 2`（最大 `536` wchar）；
   - `auto_defog.py` 通过系统命名互斥体 `Local\StellaSoraAutoDefogMutex` 确保单实例运行，每 `3.0s` 执行一次基于 `size + mtime_ns` 的极速状态扫描（缓存命中耗时约 `25ms`~`270ms`），热更新下载新包后可在几秒内自动处理，待目标游戏 PID 退出后自动结束进程。

---

## 6. Android 安卓端适配细节（`android_defog.py`）

1. **移动端纹理与目录差异**：
   - 安卓版 `char_2d_*.unity3d` 使用移动端纹理压缩格式（实测 `TextureFormat` 包含 `48`=`ASTC_4x4`、`49`=`ASTC_5x5`、`50`=`ASTC_6x6`、`51`=`ASTC_8x8` 及 `47`=`ETC2_RGBA8`），且大图集通常指向 `.resS` 外挂 `m_StreamData`；`UnityPy` / `Texture2DConverter` 重编码回写时会自动清空 `m_StreamData` 并内联写入有效压缩纹理缓冲；
   - 实机存在 `Patch_Store/AssetBundles` 与 `Persistent_Store/AssetBundles` 大量同名同哈希重叠包，`android_defog.py` 通过 `orig_sha256` 缓存（`sha_patch_cache` / `static_sha_cache`）避免重复修补与冗余 ASTC 压缩耗时，同时保证两处路径均生成对应修补文件。
2. **只读增量同步传输**：
   - **MTP 后端（`MtpTransport`）**：通过 STA 模式 PowerShell 调用 `Shell.Application` 自动探测含 `Android/data/com.RoamingStar.StellaSora/files` 的设备。由于 Windows Shell 下 MTP 文件的 `FolderItem.Size` 常返回 `0`，脚本改为读取 `ExtendedProperty("System.Size")` 与 `ExtendedProperty("System.DateModified")` 进行增量 diff，未改动资源不经 USB 拉取。
   - **ADB 后端（`AdbTransport`）**与**本地目录后端（`LocalDirTransport`）**同样只拉取元数据发生变化或尚无缓存的候选项。
3. **交付形式与分区存储兼容**：
   - 默认模式对手机**严格只读**，在 `out\android_patched\` 生成：
     - `StellaSora_Android_Defog_Patch.zip` / `StellaSora_Android_Restore_Backup.zip`（可直接配合 MT 管理器 / ZArchiver + Shizuku 覆盖导入）
     - `adb_push_patch.bat` / `adb_restore_backup.bat`
     - `shizuku_apply_patch.sh` / `shizuku_restore_backup.sh`
   - 若用户显式指定 `--apply-phone` / `--restore-phone` 或在菜单选择对应项，才执行写入或还原；并支持 `--watch` 定期轮询手机新增热更包。

---

## 7. 便携环境隔离与批处理编码兼容

1. **零宿主机污染**：
   - 精简 `runtime\` 目录内放置 `python312._pth`（内容为 `.` / `Lib` / `DLLs` / `Lib\site-packages` / `..`），在 CPython 初始化阶段直接屏蔽系统环境变量 `PYTHONPATH` / `PYTHONHOME` 与宿主机站点包。
2. **规避 Windows `cmd.exe` UTF-8 批处理解析缺陷**：
   - Windows `cmd.exe` 在 `chcp 65001` 下读取含多字节中文字符的 `.bat` 脚本时，容易在缓冲区/行解析边界发生字节截断并导致乱码及语法错位；
   - 工具集中所有顶层 `.bat` 均保持 **100% 纯 ASCII** 内容（`nonAscii=0`），仅负责设置 `chcp 65001 >nul` 与切换工作目录后立即交由 Python 渲染全部 UTF-8 中文交互界面（`android_defog.py --menu` / `auto_defog.py --interactive`）。
