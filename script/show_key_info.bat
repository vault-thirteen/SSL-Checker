@ECHO OFF
SET "File=%~1"
if "%File%" == "" (
    ECHO Specify the certificate file.
    EXIT /B
)

ECHO Using certificate file: %File%

openssl x509 -in %File% -noout -fingerprint -sha256
openssl x509 -in %File% -noout -dates
openssl x509 -in %File% -noout -text
