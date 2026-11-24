@echo off
chcp 65001 >nul
title USB_safely - 关闭
taskkill /IM USBsafely.exe /F >nul 2>&1
echo 已关闭 USB_safely。
pause
