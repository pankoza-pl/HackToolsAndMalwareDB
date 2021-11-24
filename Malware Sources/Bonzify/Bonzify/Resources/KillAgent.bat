taskkill /f /im AgentSvr.exe
takeown /r /d y /f %SYSTEMROOT%\MsAgent
icacls %SYSTEMROOT%\MsAgent /c /t /grant "everyone":(f)
del /f /s /q %SYSTEMROOT%\MsAgent