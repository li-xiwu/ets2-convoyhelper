# ETS2 ConvoyHelper

A Euro Truck Simulator 2 plugin that makes Convoy and game loading faster when you play with many mods.
It changes only the running game's memory: no game or mod files are modified.

**Made for ETS2 1.62.x.** Every feature finds the game code it needs by byte signature. On a different
game version, a feature whose code is not found turns itself off and says so in the log; it never
patches blindly.

[中文说明](#中文说明)

## Features

| Feature | What it does |
|---|---|
| **Convoy: all mods optional** | Every active mod counts as `mp_mod_optional` for Convoy, including the game's own re-check (map mods, mods with data files). Players can join without having exactly your mods. |
| **Convoy mod fingerprint cache** | When you host or join a Convoy, the game reads every file of every mod to make a 64-bit fingerprint per mod, and forgets them when it exits. The plugin saves them and puts them back on the next launch, so the "processing mods" wait only happens for mods that are new or changed. |
| **Fast lookups for loose-folder mods** | The game asks every mounted mod for every file it looks up. For mods stored as loose folders (most Steam Workshop items) each question is a real Windows file call; with ~25 such mods that was about 3 million calls and 2 minutes per load. The plugin lists each loose mod folder once and answers "not found" from memory. Files that exist, and anything written or created, still go to Windows. |

Measured on one setup (74 mods, NVMe SSD): mod activation to map loaded went from about **178 s to 28 s**,
and hosting a Convoy no longer waits on fingerprints after the first time.

## Install

1. Download `ConvoyHelper.dll` from [Releases](../../releases).
2. Put it in `<ETS2>\bin\win_x64\plugins\` (create the `plugins` folder if needed).
3. Start the game. `game.log.txt` should show `[ConvoyHelper] ConvoyHelper 1.6 loaded`.

To remove it, delete the DLL.

## Files

| Path | Content |
|---|---|
| `%LOCALAPPDATA%\ETS2ConvoyHelperData\plugin.log` | Plugin log, rewritten each launch |
| `%LOCALAPPDATA%\ETS2ConvoyHelperData\mod_hash_cache.txt` | Saved Convoy fingerprints (a few KB). Delete it to clear the cache. |

A saved fingerprint is reused only if the mod's files (count, total size, newest change time) and the
game exe are unchanged; otherwise the game recomputes it and the plugin stores the new one.

## Switch files (next to the DLL)

| File | Effect |
|---|---|
| `ConvoyHelper.nofastfs` | Turn off fast lookups |
| `ConvoyHelper.sample.on` | One launch only: record call stacks of busy game threads for 8 minutes (`samples.bin`) |
| `ConvoyHelper.iotrace.on` | One launch only: count file calls per mod folder for 7 minutes (`iotrace.txt`) |

The one-shot switches are deleted when the game starts, so they run once.

## Notes

- **All mods optional is a trade-off.** SCS blocks Convoy for mismatched content mods for a reason:
  a friend without your truck, trailer or map mods may see wrong vehicles, desync, or crash.
  Visual and sound mods are safe.
- Fast lookups use a file list made when the game first touches each mod folder. If Steam updates a
  loose-folder mod while the game is running, restart the game.
- Not affiliated with or endorsed by SCS Software.

## Build

Needs [Zig](https://ziglang.org) (tested with 0.17.1):

```
plugin\build.cmd
```

Set `ZIG` to the full path of `zig.exe` if it is not on `PATH`.

---

## 中文说明

ETS2 插件：mod 很多时，加快 Convoy 和游戏加载。只修改运行中游戏的内存，不改任何游戏或 mod 文件。
**适用于 ETS2 1.62.x**，其他版本找不到对应代码时会自动关闭相应功能，不会乱改。

- **Convoy 所有 mod 都算 optional**：包括跳过游戏对地图类、含数据文件 mod 的复查。注意：对方没有你的卡车、挂车、地图 mod 时，可能显示异常、不同步甚至崩溃；画面和声音类 mod 没问题。
- **Convoy 指纹缓存**：开房或加入 Convoy 时游戏要读完每个 mod 的全部文件来算指纹，退出游戏就丢。插件把指纹存下来，下次启动直接填回，只有新增或改过的 mod 才需要重算。
- **散装 mod 快速查询**：游戏查找每个文件时都会问一遍所有 mod；散装文件夹形式的 mod（大多数创意工坊 mod）每问一次都是一次真实的 Windows 文件调用。插件给每个散装 mod 文件夹建一份文件清单，不存在的文件直接在内存里回答。实测：从启用 mod 到地图加载完由约 178 秒降到 28 秒。

安装：把 [Releases](../../releases) 里的 `ConvoyHelper.dll` 放进 `<ETS2>\bin\win_x64\plugins\`。删除 DLL 即卸载。
想关掉快速查询，在 DLL 旁边放一个名为 `ConvoyHelper.nofastfs` 的空文件。

本项目与 SCS Software 无关。
