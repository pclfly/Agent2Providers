#!/usr/bin/env node
/**
 * 插件包裁切打包：只把 pack.json 里指定的几家编进包，并另取一个包 id。
 *
 * ── 为什么需要它（与 pack.mjs 的分工）─────────────────────────
 * `pack.mjs` 打的是**官方全量包**：包 id 固定 `agent2api-providers`、版本取自
 * `pack.json`、二进制含全部 feature。那份包由官方流水线签名并走索引分发。
 *
 * 本脚本面向「自己留一份小包」的场合：
 *   1. **另取包 id** —— 网关的最低版本校验只认两个官方 id
 *      （网关 `plugin_host/compatibility.rs` 的 `OFFICIAL_PACKS`），换一个 id
 *      即不受「插件版本不得低于网关版本」约束，也不会覆盖已装的官方包；
 *   2. **只编一家** —— `cargo build --no-default-features --features <家>`
 *      出来的二进制小一个数量级（全量 15 MB → 单家 3 MB），装到别处不必
 *      连带装上几十家；
 *   3. **不动 pack.json** —— 裁切结果是脚本内的临时清单，官方清单保持原样。
 *      想改官方包请直接编辑 `pack.json` 再走 `pack.mjs`。
 *
 * ── 为什么与 pack.mjs 复制而不是复用 ────────────────────────
 * `pack.mjs` 是顶层直接执行的 CLI（`main()` 在文件末尾调用），没有导出任何
 * 函数。为了复用六十行 zip 写入器而把它改成模块，会让「官方发版脚本」多一条
 * 被误改的路径 —— 那条路径上有签名与 CI。这里选择复制，并在改动 zip 结构时
 * **两边一起改**（网关用 `zip` crate 解包，store 模式是唯一要求）。
 *
 * ── feature 名与 provider id 不是一一对应 ───────────────────
 * `crates/providers/Cargo.toml` 里 `cline` 一个 feature 承载 `cline-free` /
 * `cline-pass` 两家，`modelscope` 承载国内 / 国际两站。所以不能把 provider id
 * 直接当 feature 用，见下面的 [`FEATURE_OF`]。
 *
 * ── 用法 ────────────────────────────────────────────────────
 * ```bash
 * # 只打 minimax，包 id 取 agent2api-minimax、版本 1.0.0
 * node scripts/pack-subset.mjs --only minimax --id agent2api-minimax --version 1.0.0
 *
 * node scripts/pack-subset.mjs --only minimax --id agent2api-minimax --skip-build
 * node scripts/pack-subset.mjs --only cline-free,cline-pass --id agent2api-cline
 * node scripts/pack-subset.mjs --only minimax --id x --target x86_64-pc-windows-msvc
 * ```
 *
 * 退出码：0 = 成功；1 = 参数 / 清单 / 构建失败。
 */

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import process from 'node:process'

const HERE = dirname(fileURLToPath(import.meta.url))
/** 插件仓库根（本脚本在 `<根>/scripts/` 下） */
const PLUGIN_DIR = resolve(HERE, '..')

/**
 * provider id → cargo feature。
 *
 * 未列出的 id 与 feature 同名（`minimax` → `minimax`）。新增一家时若 feature
 * 名与 id 不同，必须在这里补一行 —— 漏了会打出一个**不含该家**的包：cargo
 * 认得 `--features` 就会编，而清单里写着它，装上去握手时找不到 provider。
 */
const FEATURE_OF = {
  'cline-free': 'cline',
  'cline-pass': 'cline',
  'modelscope-intl': 'modelscope',
}

/** 与 `pack.mjs` 逐字一致的宿主三元组（四个消费方共用，别改写法）。 */
function hostTriple() {
  const arch = process.arch === 'x64' ? 'x86_64' : process.arch === 'arm64' ? 'aarch64' : process.arch
  switch (process.platform) {
    case 'win32': return `${arch}-pc-windows-msvc`
    case 'darwin': return `${arch}-apple-darwin`
    default: return `${arch}-unknown-linux-gnu`
  }
}

function binaryName(target) {
  return target.includes('windows') ? 'agent2api-providers.exe' : 'agent2api-providers'
}

function crc32(buffer) {
  let table = crc32.table
  if (!table) {
    table = new Uint32Array(256)
    for (let index = 0; index < 256; index += 1) {
      let value = index
      for (let bit = 0; bit < 8; bit += 1) {
        value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
      }
      table[index] = value >>> 0
    }
    crc32.table = table
  }
  let crc = 0xffffffff
  for (let index = 0; index < buffer.length; index += 1) {
    crc = table[(crc ^ buffer[index]) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

/** DOS 时间戳（固定值：同一份输入产出同一份字节，便于比对与校验）。 */
const DOS_TIME = 0
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1

/** store 模式 zip（与 `pack.mjs` 的 writeZip 同一实现，改动两边一起改）。 */
function writeZip(entries) {
  const locals = []
  const centrals = []
  let offset = 0
  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, 'utf8')
    const crc = crc32(entry.data)
    const size = entry.data.length

    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0x0800, 6)
    local.writeUInt16LE(0, 8)
    local.writeUInt16LE(DOS_TIME, 10)
    local.writeUInt16LE(DOS_DATE, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(size, 18)
    local.writeUInt32LE(size, 22)
    local.writeUInt16LE(nameBytes.length, 26)
    local.writeUInt16LE(0, 28)
    locals.push(local, nameBytes, entry.data)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE((3 << 8) | 20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0x0800, 8)
    central.writeUInt16LE(0, 10)
    central.writeUInt16LE(DOS_TIME, 12)
    central.writeUInt16LE(DOS_DATE, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(size, 20)
    central.writeUInt32LE(size, 24)
    central.writeUInt16LE(nameBytes.length, 28)
    central.writeUInt16LE(0, 30)
    central.writeUInt16LE(0, 32)
    central.writeUInt16LE(0, 34)
    central.writeUInt16LE(0, 36)
    const mode = entry.executable ? 0o100755 : 0o100644
    central.writeUInt32LE((mode << 16) >>> 0, 38)
    central.writeUInt32LE(offset, 42)
    centrals.push(central, nameBytes)

    offset += local.length + nameBytes.length + size
  }
  const centralSize = centrals.reduce((total, item) => total + item.length, 0)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(0, 4)
  end.writeUInt16LE(0, 6)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralSize, 12)
  end.writeUInt32LE(offset, 16)
  end.writeUInt16LE(0, 20)
  return Buffer.concat([...locals, ...centrals, end])
}

function parseArgs(argv) {
  const options = {
    only: '', id: '', version: '', name: '', out: join(PLUGIN_DIR, 'dist'),
    target: '', build: true, license: true, homepage: null,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    const next = () => argv[++index] || ''
    if (arg === '--only') options.only = next()
    else if (arg === '--id') options.id = next()
    else if (arg === '--version') options.version = next()
    else if (arg === '--name') options.name = next()
    else if (arg === '--out') options.out = resolve(next() || options.out)
    else if (arg === '--target') options.target = next()
    else if (arg === '--no-license') options.license = false
    else if (arg === '--skip-build') options.build = false
    else if (arg === '--help' || arg === '-h') {
      console.log('用法: node scripts/pack-subset.mjs --only <id[,id]> --id <包id> [--version <版本>]')
      console.log('       [--name <显示名>] [--target <三元组>] [--out <目录>] [--skip-build] [--no-license]')
      process.exit(0)
    } else {
      console.error(`未知参数：${arg}`)
      process.exit(1)
    }
  }
  if (!options.only.trim()) {
    console.error('缺少 --only：要打进来的 provider id（逗号分隔，例如 --only minimax）')
    process.exit(1)
  }
  if (!options.id.trim()) {
    console.error('缺少 --id：新包的 id（例如 --id agent2api-minimax）。')
    console.error('官方包 id（agent2api-providers）不在这里使用 —— 那会覆盖已装的官方包，')
    console.error('且受「插件版本不得低于网关版本」约束（见本文件头）。')
    process.exit(1)
  }
  return options
}

/**
 * 从 `pack.json` 里挑出要保留的 provider 条目。
 *
 * 顺序沿用官方清单的顺序（`pack.json` 的排列决定模型目录合并时的归属优先级），
 * 不按 `--only` 的书写顺序重排 —— 那样同一组 id 换个写法就换一份产物。
 */
function selectProviders(manifest, only) {
  const wanted = new Set(only.map(item => item.trim()).filter(Boolean))
  const declared = new Map(manifest.providers.map(item => [item.id, item]))
  const missing = [...wanted].filter(id => !declared.has(id))
  if (missing.length) {
    console.error(`pack.json 里没有这些 provider：${missing.join(', ')}`)
    console.error(`现有：${[...declared.keys()].join(', ')}`)
    process.exit(1)
  }
  const picked = manifest.providers.filter(item => wanted.has(item.id))
  // 重新编号 order：裁切后的包只有这几家，沿用原序号的空档没有意义
  return picked.map((item, index) => ({ ...item, order: index }))
}

function featureList(picked) {
  const features = new Set(picked.map(item => FEATURE_OF[item.id] || item.id))
  return [...features]
}

/**
 * 收图标目录。
 *
 * ── 这里收的是什么 ──────────────────────────────────────────
 * **包卡片**的图标：网关 `pack_view::pack_icon` 按 `logo.*` → `icon.*` →
 * 目录里任意一张图 的顺序挑一张。账号行 / 签到行的图标不来自插件包，它们读
 * 网关自己的 `ui/assets/providers/<id>.png`（`checkin-row.tsx` 那类回退路径），
 * 所以裁切包里少几张 provider 图不影响界面。
 *
 * 因此这里只按 `logo` / `icon` 两个词根找 —— 与网关的优先级同一口径，找不到
 * 就**不报错**（界面回落首字母），不为一张装饰图让打包失败。
 */
function collectIcons(manifest) {
  const iconsDir = manifest.icons
  if (!iconsDir) return []
  if (iconsDir.startsWith('/') || iconsDir.startsWith('\\') || /^[a-zA-Z]:/.test(iconsDir)) {
    console.error(`pack.json 的 icons 必须是相对路径（${iconsDir}）`)
    process.exit(1)
  }
  if (iconsDir.split(/[\\/]/).includes('..')) {
    console.error(`pack.json 的 icons 不能包含 ..（${iconsDir}）`)
    process.exit(1)
  }
  const files = []
  for (const stem of ['logo', 'icon']) {
    for (const ext of ['png', 'webp', 'jpg', 'jpeg', 'svg']) {
      const name = `${iconsDir}/${stem}.${ext}`
      const full = join(PLUGIN_DIR, name)
      if (existsSync(full) && statSync(full).isFile()) {
        files.push({ name, data: readFileSync(full), executable: false })
        break
      }
    }
  }
  return files
}

/**
 * 收 `ui/` 页面资源（清单 `ui` 字段声明的面板）。
 *
 * ── 为什么必须连文件一起收 ──────────────────────────────────
 * 清单里的 `ui` 是**声明**，网关按它生成菜单项，真实文件从包目录下的 `ui/`
 * 取（`/plugins/{pack}/ui/{entry}`）。只留声明不打包文件 = 菜单点开 404，
 * 而安装、握手、转发全都正常 —— 症状出现在离打包最远的地方。
 *
 * 所以：清单声明了 `ui` 就必须带上 `ui/` 目录；目录不存在时**删掉声明**而不是
 * 留一个空指针（宁可少一个面板入口，也不要一个必然 404 的入口）。
 */
function collectUi(manifest) {
  const pages = Array.isArray(manifest.ui) ? manifest.ui : []
  if (!pages.length) return { files: [], pages: [] }
  const root = join(PLUGIN_DIR, 'ui')
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    console.warn('[subset] 清单声明了 ui 页面，但仓库里没有 ui/ 目录：已从清单中移除这些页面')
    return { files: [], pages: [] }
  }
  const files = []
  const walk = current => {
    for (const item of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, item.name)
      if (item.isDirectory()) walk(full)
      else if (item.isFile()) {
        const name = relative(PLUGIN_DIR, full).split('\\').join('/')
        files.push({ name, data: readFileSync(full), executable: false })
      }
    }
  }
  walk(root)
  // entry 以 `ui/` 为基准（网关 `resolve_ui_file` 去掉 `/ui/` 前缀后再找），
  // 这里按同一口径核对每个声明页面的文件是否真的在包里
  const present = new Set(files.map(file => file.name.replace(/^ui\//, '')))
  const kept = pages.filter(page => {
    const entry = String(page.entry || '').replace(/\\/g, '/')
    if (present.has(entry)) return true
    console.warn(`[subset] ui 页面 ${page.id} 的 ${entry} 不在包里：已从清单中移除`)
    return false
  })
  return { files: files.sort((left, right) => left.name.localeCompare(right.name)), pages: kept }
}

function main() {
  const options = parseArgs(process.argv.slice(2))
  const host = hostTriple()
  const target = options.target || host

  const manifestPath = join(PLUGIN_DIR, 'pack.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const declared = manifest.entry?.[target]
  if (!declared) {
    console.error(`pack.json 的 entry 里没有目标平台（${target}）`)
    console.error(`现有条目：${Object.keys(manifest.entry || {}).join(', ') || '(空)'}`)
    process.exit(1)
  }
  const expectedName = binaryName(target)
  if (declared.split('/').pop() !== expectedName) {
    console.error(`pack.json 的 entry（${declared}）与二进制名（${expectedName}）不一致`)
    process.exit(1)
  }

  const only = options.only.split(',')
  const picked = selectProviders(manifest, only)
  const features = featureList(picked)
  const version = options.version.trim() || manifest.version
  const name = options.name.trim() || `${manifest.name}（${picked.map(item => item.label).join(' / ')}）`

  // 与 pack.mjs 同一套产物路径规则：交叉编译时不能误取宿主架构的旧产物
  const targetDir = process.env.CARGO_TARGET_DIR
    ? resolve(PLUGIN_DIR, process.env.CARGO_TARGET_DIR)
    : join(PLUGIN_DIR, 'target')
  const native = target === host
  const exe = native
    ? join(targetDir, 'release', binaryName(target))
    : join(targetDir, target, 'release', binaryName(target))

  if (options.build) {
    const args = ['build', '--release', '-p', 'agent2api-providers', '--no-default-features']
    args.push('--features', features.join(','))
    if (!native) args.push('--target', target)
    console.log(`[subset] 编译（cargo ${args.join(' ')}）…`)
    execFileSync('cargo', args, { cwd: PLUGIN_DIR, stdio: 'inherit' })
  }
  if (!existsSync(exe)) {
    console.error(`[subset] 找不到 release 二进制：${exe}`)
    console.error(`[subset] 先跑 \`cargo build --release --no-default-features --features ${features.join(',')}\`，或去掉 --skip-build`)
    process.exit(1)
  }

  /**
   * 打包前**核对二进制里真的有这几家**。
   *
   * 这是本脚本唯一能自证「清单与二进制一致」的地方：`--features` 写错、或
   * 二进制是上一次别的 feature 组合留下的（`--skip-build` 时最容易），产物
   * 都会是「清单声明 A、二进制只有 B」。装上去的症状是握手缺家，而错误显示
   * 在插件页，离打包这一步很远。所以用 provider id 的字节出现次数粗判 ——
   * 误判方向是「漏报」（字符串被优化掉时数不到），不会把缺的判成有。
   */
  const binary = readFileSync(exe)
  const absent = picked.filter(item => binary.indexOf(Buffer.from(item.id, 'utf8')) < 0)
  if (absent.length) {
    console.error(`[subset] 二进制里找不到这些 provider 的痕迹：${absent.map(item => item.id).join(', ')}`)
    console.error(`[subset] 该二进制可能不是用 --features ${features.join(',')} 编出来的；去掉 --skip-build 重编`)
    process.exit(1)
  }

  const icons = collectIcons(manifest)
  const ui = collectUi(manifest)
  const subsetManifest = {
    ...manifest,
    id: options.id.trim(),
    name,
    version,
    providers: picked,
  }
  // 主键顺序与官方清单一致，diff 时可读
  const ordered = {
    id: subsetManifest.id,
    name: subsetManifest.name,
    description: subsetManifest.description,
    license: subsetManifest.license,
    version: subsetManifest.version,
    protocol: subsetManifest.protocol,
    providers: subsetManifest.providers,
    icons: subsetManifest.icons,
    entry: subsetManifest.entry,
    homepage: manifest.homepage,
  }
  // 只在还真有页面时写 `ui` 键：写一个空数组与「没有这个字段」在同一条
  // 判据上等价，但少一个键的清单读起来更明确
  if (ui.pages.length) ordered.ui = ui.pages

  const zipName = `${ordered.id}-${version}-${target}.zip`
  const zipPath = join(options.out, zipName)
  mkdirSync(options.out, { recursive: true })

  const entries = [{ name: 'pack.json', data: Buffer.from(`${JSON.stringify(ordered, null, 2)}\n`, 'utf8'), executable: false }]
  entries.push(...icons)
  entries.push(...ui.files)
  if (options.license && existsSync(join(PLUGIN_DIR, 'LICENSE'))) {
    entries.push({ name: 'licenses/LICENSE', data: readFileSync(join(PLUGIN_DIR, 'LICENSE')), executable: false })
  }
  entries.push({ name: declared, data: binary, executable: true })

  writeFileSync(zipPath, writeZip(entries))

  console.log(`[subset] 平台      ${target}${native ? '（宿主）' : '（交叉）'}`)
  console.log(`[subset] 包 id     ${ordered.id} v${version}`)
  console.log(`[subset] 提供商    ${picked.map(item => item.id).join(', ')}`)
  console.log(`[subset] features  ${features.join(', ')}`)
  console.log(`[subset] 二进制    ${(binary.length / 1024 / 1024).toFixed(2)} MB`)
  console.log(`[subset] 图标      ${icons.length ? icons.map(item => item.name).join(', ') : '无'}`)
  console.log(`[subset] 页面      ${ui.pages.length ? `${ui.pages.length} 个（${ui.files.length} 个文件）` : '无'}`)
  console.log(`[subset] 插件包    ${zipPath}`)
  console.log('[subset] 安装方式：网关界面 → 提供商插件 → 安装插件包，选中这个 zip')
}

main()
