# 本地 proto 生成管线（BSR 不可达环境的等价实现）
# 与 buf.gen.yaml 注释中的命令保持一致：
#   protoc + protoc-gen-go v1.36.11 + protoc-gen-go-grpc v1.6.2
# 前置安装：
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
#   protoc 二进制（https://github.com/protocolbuffers/protobuf/releases，解压到 %USERPROFILE%\protoc）
# 若 BSR 可达，可改用：buf generate api/proto
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$protoc = (Get-Command protoc -ErrorAction SilentlyContinue).Source
if (-not $protoc) {
    $candidate = Join-Path $env:USERPROFILE "protoc\bin\protoc.exe"
    if (Test-Path $candidate) { $protoc = $candidate }
}
if (-not $protoc -or -not (Test-Path $protoc)) {
    throw "未找到 protoc：请下载 protoc 发布包并解压，或将其加入 PATH"
}

$gobin = Join-Path $env:USERPROFILE "go\bin"
$env:PATH = "$gobin;" + $env:PATH
foreach ($plugin in @("protoc-gen-go.exe", "protoc-gen-go-grpc.exe")) {
    if (-not (Test-Path (Join-Path $gobin $plugin))) {
        throw "缺少 $plugin：请执行 go install 安装（版本见文件头注释）"
    }
}

# M 映射强制生成代码内跨文件 import 使用完整模块路径
$M = "paths=source_relative" +
     ",Meiam/user/v1/user.proto=github.com/Havens-blog/e-iam/api/proto/gen/eiam/user/v1" +
     ",Meiam/tenant/v1/tenant.proto=github.com/Havens-blog/e-iam/api/proto/gen/eiam/tenant/v1" +
     ",Meiam/department/v1/department.proto=github.com/Havens-blog/e-iam/api/proto/gen/eiam/department/v1"

& $protoc -I api/proto `
    --go_out=api/proto/gen --go-grpc_out=api/proto/gen `
    "--go_opt=$M" "--go-grpc_opt=$M" `
    api/proto/eiam/user/v1/user.proto `
    api/proto/eiam/tenant/v1/tenant.proto `
    api/proto/eiam/department/v1/department.proto

if ($LASTEXITCODE -ne 0) { throw "protoc 生成失败" }
Write-Host "proto 生成完成：api/proto/gen 下 6 个产物已刷新"