@echo off
setlocal
set CONFIGURATION=%1
if "%CONFIGURATION%"=="" set CONFIGURATION=Debug

echo === AgentGuard Build (%CONFIGURATION%) ===
pushd %~dp0\..

dotnet restore AgentGuard.slnx
if errorlevel 1 exit /b 1

dotnet build AgentGuard.slnx --no-restore --configuration %CONFIGURATION%
if errorlevel 1 exit /b 1

dotnet test AgentGuard.slnx --no-build --configuration %CONFIGURATION% --verbosity normal
if errorlevel 1 exit /b 1

echo Build complete.
popd
