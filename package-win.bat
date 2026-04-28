@echo off
setlocal EnableDelayedExpansion

:: ============================================================
::  CACertsViewer — Windows 打包脚本
::  输出: dist\CACertsViewer\CACertsViewer.exe  (双击即可运行)
:: ============================================================

set APP_NAME=CACertsViewer
set APP_VERSION=0.1.0
set MAIN_CLASS=com.ctgu.CacertsViewerApp
set FAT_JAR=%APP_NAME%-%APP_VERSION%-fat.jar

:: 使用绝对路径（jpackage 要求 --input 为绝对路径）
set SCRIPT_DIR=%~dp0
set INPUT_DIR=%SCRIPT_DIR%target\jpackage-input
set DIST_DIR=%SCRIPT_DIR%dist

:: ---- 定位 jpackage ----
set JPACKAGE=jpackage
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\jpackage.exe" (
        set JPACKAGE="%JAVA_HOME%\bin\jpackage.exe"
    )
)

echo.
echo ====================================================
echo   CACertsViewer  ^|  Windows Packager
echo ====================================================

:: ---- Step 1: 编译并打包 fat JAR ----
echo.
echo [1/3] 正在构建 fat JAR (mvn package)...
call mvn package -q -DskipTests
if errorlevel 1 (
    echo.
    echo [ERROR] Maven 构建失败，请检查上方错误信息。
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%target\%FAT_JAR%" (
    echo.
    echo [ERROR] 未找到 target\%FAT_JAR%，构建可能未成功。
    pause
    exit /b 1
)
echo        完成：target\%FAT_JAR%

:: ---- Step 2: 准备 jpackage 输入目录 ----
echo.
echo [2/3] 准备打包输入目录...
if exist "%INPUT_DIR%" rmdir /s /q "%INPUT_DIR%"
mkdir "%INPUT_DIR%"
copy /y "%SCRIPT_DIR%target\%FAT_JAR%" "%INPUT_DIR%\" >nul

:: ---- Step 3: 运行 jpackage 生成 app-image ----
echo.
echo [3/3] 正在运行 jpackage，生成独立 Windows 应用...
echo       (首次运行需打包 JRE，可能需要 1~3 分钟)
echo.

if exist "%DIST_DIR%\%APP_NAME%" (
    echo       清理旧版本...
    rmdir /s /q "%DIST_DIR%\%APP_NAME%"
)

%JPACKAGE% ^
  --type app-image ^
  --name "%APP_NAME%" ^
  --app-version "%APP_VERSION%" ^
  --description "Java 证书库管理器 (JKS / PKCS12)" ^
  --vendor "ctgu" ^
  --input "%INPUT_DIR%" ^
  --main-jar "%FAT_JAR%" ^
  --main-class "%MAIN_CLASS%" ^
  --dest "%DIST_DIR%" ^
  --java-options "-Dfile.encoding=UTF-8" ^
  --java-options "-Dswing.aatext=true" ^
  --java-options "-Dawt.useSystemAAFontSettings=on" ^
  --java-options "-Dsun.java2d.uiScale.enabled=true"

:: 提示：若需自定义图标，添加以下参数（ICO 格式）:
::   --icon "%SCRIPT_DIR%src\main\resources\icon.ico"

if errorlevel 1 (
    echo.
    echo [ERROR] jpackage 失败。
    echo         请确保已安装 JDK 21+，且 jpackage 在 PATH 中或 JAVA_HOME 已设置。
    pause
    exit /b 1
)

:: ---- 清理临时文件 ----
rmdir /s /q "%INPUT_DIR%" 2>nul

echo.
echo ====================================================
echo   打包成功！
echo.
echo   可执行文件: %DIST_DIR%\%APP_NAME%\%APP_NAME%.exe
echo   直接双击上述 .exe 即可运行，无需安装 Java。
echo ====================================================
echo.
pause
