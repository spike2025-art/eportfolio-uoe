@echo off
REM ================================================================
REM  STEP 2 of 4 — Launch Jupyter in the dissertation folder
REM
REM  HOW TO RUN:
REM    1. Open a FRESH Anaconda Prompt
REM    2. Navigate to:  C:\Users\Owner\OneDrive\dissertation
REM    3. Double-click this file  OR  type:  STEP2_launch_jupyter.bat
REM
REM  IMPORTANT: When Jupyter opens in your browser,
REM    select kernel  "Python (finbert_env)"  in every notebook.
REM ================================================================

echo.
echo  Activating finbert_env ...
call conda activate finbert_env

echo.
echo  Changing to dissertation notebooks folder ...
cd /d "C:\Users\Owner\OneDrive\dissertation\notebooks"

echo.
echo ================================================================
echo  Starting Jupyter Notebook
echo  Folder : C:\Users\Owner\OneDrive\dissertation\notebooks
echo  Kernel : Python (finbert_env)
echo.
echo  In every notebook:
echo    Kernel menu ^> Change Kernel ^> Python (finbert_env)
echo ================================================================
echo.

jupyter notebook
pause
