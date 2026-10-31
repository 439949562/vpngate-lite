# reoptimize.ps1 — 一键重新优选入口
# 流程: CloudflareSpeedTest 本机测速 -> 筛出可用 IP -> 更新仓库 edge_hosts.txt -> 触发 Actions
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File reoptimize.ps1
# 前提: ego lite 已登录 GitHub（登录态在 Profile 1）；代理可用（cfst 本身直连，不需要代理）

$ErrorActionPreference = 'Stop'
$RepoDir  = "E:\DSHWS\ariport\vpngate-lite"
$CfstDir  = "E:\DSHWS\ariport\tools\cfst"
$EdgeFile = "$RepoDir\edge_hosts.txt"

# --- 1. cfst 测速 ---
Write-Host "[1/4] CloudflareSpeedTest 测速中（约 6~8 分钟）..."
Push-Location $CfstDir
& .\cfst.exe -n 200 -t 4 -tl 250 -dn 20 -dt 10 -tp 443 -p 20 -o result.csv 2>$null | Out-Null
Pop-Location
if (-not (Test-Path "$CfstDir\result.csv")) { throw "cfst 没有产出 result.csv" }

# --- 2. 筛选 ---
Write-Host "[2/4] 筛选入口..."
$csv = Import-Csv "$CfstDir\result.csv" -Encoding UTF8
$good = $csv | Where-Object { [double]$_.'丢包率' -eq 0 -and [double]$_.'下载速度(MB/s)' -gt 0 } |
        Sort-Object { [double]$_.'下载速度(MB/s)' } -Descending
if (-not $good -or $good.Count -lt 3) { throw "可用入口不足 3 个（$($good.Count) 个），本轮放弃" }
Write-Host ("  筛出 {0} 个可用入口" -f $good.Count)

# --- 3. 生成新 edge_hosts.txt（保留用户中转组） ---
$relayLines = @()
if (Test-Path $EdgeFile) {
    $src = Get-Content $EdgeFile -Encoding UTF8
    $idx = ($src | Select-String -Pattern '【第二组】').LineNumber
    if ($idx) { $relayLines = $src[$idx..($src.Count - 1)] | Where-Object { $_ -match '^\d' } }
}
Write-Host ("  保留中转入口 {0} 个" -f $relayLines.Count)

$header = @(
    '# vpngate-lite 入口池（edgetunnel「自定义优选IP」用）',
    '# 每行一个入口：IP:端口 或 域名:端口（缺端口默认 443），# 后是注释',
    '# 要求：能路由到 Cloudflare 边缘（CF 自有段或 SNI→CF 中转）',
    '# 改完提交后，下一次 Actions 运行（每小时 :13/:43）自动生效',
    '#',
    '# 【第一组】CloudflareSpeedTest 自测（' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + '，下载>0 零丢包）'
)
$group1 = $good | ForEach-Object { $_.'IP 地址' + ':443' }
$group2 = @('#', '# 【第二组】自用中转入口（SNI→CF 透明转发）') + $relayLines
$newContent = ($header + $group1 + $group2 | ForEach-Object { $_ }) -join "`n" + "`n"
[System.IO.File]::WriteAllText($EdgeFile, $newContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("  已写入 {0}（共 {1} 个入口）" -f $EdgeFile, ($group1.Count + $relayLines.Count))

# --- 4. 经 ego-browser 提交到 GitHub 并触发 Actions ---
Write-Host "[3/4] 提交到 GitHub（ego-browser）..."
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$mjsDir = "$RepoDir\ego"
$contentLiteral = [System.IO.File]::ReadAllText($EdgeFile, [System.Text.Encoding]::UTF8)

# 生成提交用的 .mjs（内容以 JSON 字符串内嵌，避免转义问题）
$payload = @{ content = $contentLiteral } | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText("$mjsDir\reopt-payload.json", $payload, (New-Object System.Text.UTF8Encoding($false)))

$mjs = @'
const fs = await import("node:fs/promises");
const payload = JSON.parse(await fs.readFile("E:/DSHWS/ariport/vpngate-lite/ego/reopt-payload.json", "utf8"));
const content = payload.content;
const task = await taskSpace("github vpngate-lite p2");
const page = task.page("p1");
await page.goto("https://github.com/439949562/vpngate-lite/edit/main/edge_hosts.txt");
await page.waitForLoadState("load");
await page.waitForSelector(".cm-content", { timeout: 30000 });
await page.click(".cm-content", { label: "code editor" });
await page.keyboard.press("ControlOrMeta+a");
await page.keyboard.insertText(content);
await page.waitForTimeout(800);
await page.click("loc=role:button[name*='Commit changes']", { label: "open commit dialog" });
await page.waitForTimeout(1500);
const dlg = await page.evaluate(() => {
  const d = document.querySelector("dialog[open], [role=dialog]");
  if (!d) return "no dialog";
  const btn = [...d.querySelectorAll("button")].find(b => b.textContent.trim() === "Commit changes");
  if (btn) { btn.click(); return "committed"; }
  return "no confirm btn";
});
console.log("commit =", JSON.stringify(dlg));
await page.waitForTimeout(3000);
// 触发 Actions
await page.goto("https://github.com/439949562/vpngate-lite/actions/workflows/probe.yml");
await page.waitForLoadState("load");
await page.click("loc=role:button[name='Run workflow']", { label: "open run dropdown" });
await page.waitForTimeout(1200);
const dlg2 = await page.evaluate(() => {
  const d = document.querySelector("dialog[open], [role=dialog]");
  if (!d) return "no dialog";
  const btn = [...d.querySelectorAll("button")].find(b => b.textContent.trim() === "Run workflow");
  if (btn) { btn.click(); return "dispatched"; }
  return "no confirm btn";
});
console.log("dispatch =", JSON.stringify(dlg2));
'@
[System.IO.File]::WriteAllText("$mjsDir\reopt-push.mjs", $mjs, (New-Object System.Text.UTF8Encoding($false)))
ego-browser nodejs -e "await import('file:///E:/DSHWS/ariport/vpngate-lite/ego/reopt-push.mjs')" 2>&1 | Out-String

Write-Host "[4/4] 完成。Actions 已触发，7~10 分钟后 nodes.txt 自动更新。"
Write-Host "订阅源不变: https://raw.githubusercontent.com/439949562/vpngate-lite/main/out/nodes.txt"
