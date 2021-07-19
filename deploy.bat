set mydate=%date:/=%
set TIMESTAMP=%mydate: =_%
set OUTPUT=net-doctor-%TIMESTAMP%
rmdir /S /Q %OUTPUT%
mkdir %OUTPUT%
set SRC=%~dp0

robocopy %SRC%/bin %OUTPUT%/bin *
robocopy %SRC%/dpkt %OUTPUT%/dpkt *
robocopy %SRC% %OUTPUT% nd.py
robocopy %SRC% %OUTPUT% trace_viewer.html
robocopy %SRC% %OUTPUT% run.bat

makecab %OUTPUT% %OUTPUT%.zip