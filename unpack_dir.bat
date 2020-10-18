@echo off
set MY_DIR=%1%
for %%f in ( %MY_DIR%\*) do (
	echo "unpacking: %%f"
	mal_unpack.exe /exe %%f /timeout 0 /dir %%f.out
)
echo "unpacking completed"
pause
