@echo off
chcp 65001 >nul
title USB_safely - 设置
start "" "%~dp0USBsafely.exe" setup
