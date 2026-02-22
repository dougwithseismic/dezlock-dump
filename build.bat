@echo off
cmake -B build -G "Visual Studio 17 2022" -A x64 || exit /b 1
cmake --build build --config Release || exit /b 1
echo.
echo Build complete! Output in build\bin\Release\
