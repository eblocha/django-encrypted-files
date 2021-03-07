Django Encrypted Files
======================

Encrypt files uploaded to your Django application.

Usage
-----

Add the `encrypted_files` app to your `INSTALLED_APPS` setting:
`settings.py`
```python
INSTALLED_APPS = [
    ...
    'encrypted_files',
    ...
]
```

Add an encryption key to use. This should be 16, 24, or 32 bytes long:

`settings.py`
```python
AES_KEY = b'\x1a>\xf8\xcd\xe2\x8e_~V\x14\x98\xc2\x1f\xf9\xea\xf8\xd7c\xb3`!d\xd4\xe3+\xf7Q\x83\xb5~\x8f\xdd'
```

If you want to encrypt ALL uploaded files, add the `EncryptedFileUploadHandler` as the first handler:

`settings.py`
```python
FILE_UPLOAD_HANDLERS = [
    "encrypted_files.uploadhandler.EncryptedFileUploadHandler",
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler"
]
```

Use regular FileFields for file uploads. When you want to decrypt the file, use the `EncryptedFile` helper class

`views.py`
```python
from .models import ModelWithFile
from encrypted_files.base import EncryptedFile as EF
from django.http import HttpResponse

def decrypted(request,pk):
    f = ModelWithFile.objects.get(pk=pk).file
    ef = EF(f)
    return HttpResponse(ef.read())
```