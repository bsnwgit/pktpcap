@echo off
setlocal
cd /d "%~dp0"

echo.
echo  PktAnalyzer — Git Setup and Push
echo  ─────────────────────────────────────────────────────

:: Remove any broken .git from a previous attempt
if exist ".git" (
    echo  Removing previous .git folder...
    rmdir /s /q ".git"
)

echo  Initializing repository...
git init -b main
git config user.email "robert.barnett@vynedental.com"
git config user.name "Robert Barnett"

echo  Staging files...
git add -A
git status --short

echo.
echo  Committing...
git commit -m "Initial commit: Packet Capture Analyzer web service"

echo.
echo  Adding remotes...
git remote add github  git@github.com:bsnwgit/pktanalyzer.git
git remote add gitlab  git@gitlab.com:robert.barnett/pktanalyzer.git

echo.
echo  Pushing to GitHub...
git push -u github main

echo.
echo  Pushing to GitLab...
git push -u gitlab main

echo.
echo  Done!
pause
