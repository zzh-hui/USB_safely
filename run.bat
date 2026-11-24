@echo off
chcp 65001 >nul
title USB_safely - 启动锁定
echo 正在启动 USB 锁...
start "" "%~dp0USBsafely.exe"
