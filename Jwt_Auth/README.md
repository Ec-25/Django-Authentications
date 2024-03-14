# Django REST Framework Complete Authentication API with Simple JWT
Django authenticator with JWT and Rest framework as an API, ready to implement.


## Installation
### main/settings.py
```
from datetime import timedelta

INSTALLED_APPS = [
    ...,
    'corsheaders',
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'accounts',
]

MIDDLEWARE = [
    ...,
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
]

# AUTH config
AUTH_USER_MODEL = 'Accounts.User'

# Mail config
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "server@email"
EMAIL_HOST_PASSWORD = "emailToken"
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# CORS config
CORS_ALLOWED_ORIGINS = getenv('CORS_ALLOWED_ORIGINS').split(',')

# Rest Framework config
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    )
}

# JWT config
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'AUTH_HEADER_TYPES': ('Bearer',),
}
```
### main/urls.py
```
from django.urls import path, include

urlpatterns = [
    ...,
    path('auth/', include('Accounts.urls')),
]
```

### accounts/utils.py
```
func -> send_verification_email() -> modify msg
func -> send_password_reset_email() -> modify msg
```