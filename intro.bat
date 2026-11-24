@echo off
chcp 65001 >nul
title USB_safely - 说明
echo ============================================
echo   USB_safely U盘锁 v0.1.0
echo ============================================
echo   run.bat   : 启动锁屏（锁住电脑）
echo   Lock.bat  : 同 run.bat
echo   setup.bat : 设置模式（修改密码/关于）
echo   clean.bat : 清除密码文件（慎用!）
echo   Close.bat : 关闭正在运行的锁屏
echo   Stoprun.bat : 同 Close.bat
echo.
echo 密码存储位置: password\pw.sf (SHA256)
echo 制作: JAC · Geek-Hub
pause
