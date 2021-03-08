Django Encrypted Files
======================

Encrypt files uploaded to your Django application.

This package uses AES in CTR mode to encrypt files via an upload handler.

The upload handler encrypts data as it is recieved during upload, so only encrypted data is ever written to temporary files.

Files can then be decrypted with the included `EncryptedFile` class, which is a file-like object that decrypts data transparently.

Installation
------------
Via pip:
```
pip install django-encrypted-files
```

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

You can also use the encrypted file upload handler for a specific view:

`views.py`
```python
from .models import ModelWithFile
from django.core.files.uploadhandler import MemoryFileUploadHandler, TemporaryFileUploadHandler
from django.views.generic.edit import CreateView
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt, csrf_protect

@method_decorator(csrf_exempt, 'dispatch')
class CreateEncryptedFile(CreateView):
    model = ModelWithFile
    fields = ["file"]

    def post(self, request, *args, **kwargs):
        request.upload_handlers = [
            EncryptedFileUploadHandler(request=request),
            MemoryFileUploadHandler(request=request),
            TemporaryFileUploadHandler(request=request)
        ]  
        return self._post(request)

    @method_decorator(csrf_protect)
    def _post(self, request):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

```

Use regular FileFields for file uploads. When you want to decrypt the file, use the `EncryptedFile` helper class

`views.py`
```python
from .models import ModelWithFile
from encrypted_files.base import EncryptedFile
from django.http import HttpResponse

def decrypted(request,pk):
    f = ModelWithFile.objects.get(pk=pk).file
    ef = EncryptedFile(f)
    return HttpResponse(ef.read())
```

The `EncryptedFileUploadHandler` and `EncryptedFile` classes also take a `key` input if you want to use a custom key (based on the user, for example):

```python
handler = EncryptedFileUploadHandler(request=request,key=custom_key_for_this_request)
```

You would then use the same key when decrypting:

```python
ef = EncryptedFile(file,key=custom_key_for_this_request)
```

The `EncryptedFile` class is a wrapper around django's `File` class. It performs the decryption and counter/pointer management when .read() and .seek() are called. It can be used as a file-like object for other processing purposes, but is read-only.

