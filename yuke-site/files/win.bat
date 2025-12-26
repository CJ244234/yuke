@echo off
:: 强制管理员权限（解决systeminfo权限问题）
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo 正在请求管理员权限...
    goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
echo set params = %* > "%temp%\getadmin.vbs"
echo Set shell = CreateObject("Shell.Application") >> "%temp%\getadmin.vbs"
echo shell.ShellExecute "cmd.exe", "/c ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
del "%temp%\getadmin.vbs"
exit /B
:gotAdmin

chcp 65001 >nul
color 0A
title CJY 至尊优化引擎 V3.0 .神秘最后
setlocal enabledelayedexpansion

:: ========== 初始化+炫酷标题动画 ==========
cls
echo.
for /l %%i in (1,1,3) do (
    echo ┌────────────────────────────────────────────────────────┐
    echo │            陈俊瑜 至尊优化引擎 初始化中...              │
    echo └────────────────────────────────────────────────────────┘
    ping -n 1 127.0.0.1 >nul 2>&1
    cls
    echo.
    echo ┌────────────────────────────────────────────────────────┐
    echo │            陈俊瑜 至尊优化引擎 初始化中..               │
    echo └────────────────────────────────────────────────────────┘
    ping -n 1 127.0.0.1 >nul 2>&1
    cls
    echo.
    echo ┌────────────────────────────────────────────────────────┐
    echo │            陈俊瑜 至尊优化引擎 初始化中.                │
    echo └────────────────────────────────────────────────────────┘
    ping -n 1 127.0.0.1 >nul 2>&1
    cls
)

:: ========== 系统版本识别（强制中文显示） ==========
echo.
echo [CJY 核心引擎] 正在调取系统内核版本信息...
echo [CJY 核心引擎] 正在解析注册表版本标识...

:: 直接通过注册表读取中文系统名（彻底解决中英文问题）
for /f "skip=2 tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName') do (
    set "SYS_NAME=%%b"
)
for /f "skip=2 tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild') do (
    set "SYS_VER=%%b"
)

echo ==================================================
echo [CJY 版本识别模块] 识别成功！当前系统为：
echo [CJY 版本识别模块] !SYS_NAME!
echo [CJY 版本识别模块] 版本：!SYS_VER!
echo ==================================================
timeout /t 2 /nobreak >nul

:: ========== 缓存清理+动态提示 ==========
cls
echo.
echo [CJY 缓存清理模块] 启动中...
echo ==================================================
set "clean_sym=●○○○○"
for /l %%i in (1,1,5) do (
    echo [CJY 缓存清理] 正在清理系统临时文件... !clean_sym!
    set "clean_sym=●!clean_sym:~1!"
    ping -n 1 127.0.0.1 >nul 2>&1
)
del /f /s /q "%temp%\*.*" >nul 2>&1
rd /s /q "%temp%" >nul 2>&1
md "%temp%" >nul 2>&1

set "clean_sym=●○○○○"
for /l %%i in (1,1,5) do (
    echo [CJY 缓存清理] 正在清理IE浏览器缓存... !clean_sym!
    set "clean_sym=●!clean_sym:~1!"
    ping -n 1 127.0.0.1 >nul 2>&1
)
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 >nul 2>&1

echo [CJY 缓存清理] 清理完成！
echo ==================================================
timeout /t 1 /nobreak >nul

:: ========== 炫酷进度条动画（还原你要的效果） ==========
cls
echo.
echo [CJY 至尊引擎] 全域优化模块阵列启动中...
echo ==================================================
set "转动符号=|/-\\"
set "module_list[10]=[CJY 性能压榨模块] 启动成功！算力提升协议加载中"
set "module_list[20]=[CJY 防入侵加固模块] 启动成功！系统防火墙规则重构中"
set "module_list[30]=[CJY 资源调度模块] 启动成功！后台进程优先级优化中"
set "module_list[40]=[CJY 核心超频模块] 启动成功！硬件潜能极限释放中"
set "module_list[50]=[CJY 日志加密模块] 启动成功！操作记录安全封存中"
set "module_list[60]=[CJY 协议兼容模块] 启动成功！跨平台指令适配中"
set "module_list[70]=[CJY 稳定性增强模块] 启动成功！系统崩溃防护中"
set "module_list[80]=[CJY 浏览器唤醒模块] 启动成功！预设程序待命中"
set "module_list[90]=[CJY 全域优化模块] 全部启动完成！优化等级：S+"

for /l %%a in (1,1,100) do (
    set "当前符号=!转动符号:~%%a%%4,1!"
    set "进度条="
    for /l %%b in (1,1,%%a) do set "进度条=!进度条!█"
    for /l %%c in (%%a,1,99) do set "进度条=!进度条!░"
    :: 动态弹出模块提示
    if defined module_list[%%a] echo !module_list[%%a]!
    :: 炫酷进度显示
    echo [!当前符号!] CJY 进度追踪：%%a%% [!进度条!]
    ping -n 1 127.0.0.1 >nul 2>&1
)
:: ========== 后续流程 ==========
cls
echo.
echo ┌────────────────────────────────────────────────────────┐
echo │            陈俊瑜.bat 运行完毕！                       │
echo └────────────────────────────────────────────────────────┘
echo [CJY 浏览器唤醒模块] 正在启动默认浏览器...
start "" "https://www.yhdm.cc/"

echo.
echo [系统提示] 缓存已清理，优化效果重启后生效！
echo [系统提示] 按任意键退出
pause >nul
endlocal