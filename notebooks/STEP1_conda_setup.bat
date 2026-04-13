@echo off
REM ================================================================
REM  STEP 1 of 4 — Create finbert_env Conda Environment
REM
REM  HOW TO RUN:
REM    1. Open "Anaconda Prompt" from the Windows Start menu
REM    2. Type:  cd C:\Users\Owner\OneDrive\dissertation
REM    3. Type:  STEP1_conda_setup.bat
REM    4. Wait until you see "ALL DONE" at the bottom
REM ================================================================

echo.
echo ================================================================
echo  Creating finbert_env  (Python 3.10)
echo  This will take 3-5 minutes
echo ================================================================
echo.

call conda create -n finbert_env python=3.10 -y
if errorlevel 1 (
    echo ERROR: conda create failed. Is Anaconda installed?
    pause
    exit /b 1
)

echo.
echo ================================================================
echo  Activating finbert_env
echo ================================================================
call conda activate finbert_env

echo.
echo ================================================================
echo  Installing PyTorch (CPU version)
echo ================================================================
pip install torch==2.2.2 --index-url https://download.pytorch.org/whl/cpu

echo.
echo ================================================================
echo  Installing Hugging Face Transformers and tokeniser
echo ================================================================
pip install transformers==4.40.0
pip install sentencepiece

echo.
echo ================================================================
echo  Installing data science and notebook libraries
echo ================================================================
pip install pandas==2.2.0 openpyxl tqdm ipykernel jupyter scipy

echo.
echo ================================================================
echo  Registering finbert_env as a Jupyter kernel
echo ================================================================
python -m ipykernel install --user --name finbert_env --display-name "Python (finbert_env)"

echo.
echo ================================================================
echo  Verifying installation — all lines should show a version number
echo ================================================================
python -c "import transformers; print('transformers :', transformers.__version__)"
python -c "import torch;        print('torch        :', torch.__version__)"
python -c "import pandas;       print('pandas       :', pandas.__version__)"
python -c "import tqdm;         print('tqdm         :', tqdm.__version__)"
python -c "print('Kernel registration : OK')"

echo.
echo ================================================================
echo  ALL DONE.
echo.
echo  Next step — open a NEW Anaconda Prompt and run:
echo    STEP2_launch_jupyter.bat
echo ================================================================
pause
