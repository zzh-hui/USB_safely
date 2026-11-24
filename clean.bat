@echo off
chcp 65001 >nul
title USB_safely - 清除密码
echo 警告: 此操作将删除密码文件, 下次需重新设置密码!
pause
if exist "%~dp0password\pw.sf" (del "%~dp0password\pw.sf" && echo 已删除密码文件。) else (echo 未找到密码文件。)
pause
