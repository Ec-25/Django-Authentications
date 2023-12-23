# Simple_Auth Module by Ec25
This module is for quick access to serve as an authenticator for clients, it uses existing users in the system and does not provide a way to create them, at the moment.

# Instalation Guide
In the root folder of the project add the Simple_Auth module, and add the configurations in **settings.py** and **urls.py**.

### In **settings.py** add:
```
INSTALLED_APPS = [
    ...
    'django.contrib...,
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'Simple_Auth',
]

MIDDLEWARE = [
    ...,
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    ...,
]
```
```
# Rest Framework Configs
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ]
}

# Simple_Auth Configs
AUTH_TOKEN_LIFETIME = 60 * 60 * 24 * 7 # 7 days
```

### In **urls.py** add at path:
```
from django.urls import include, path

urlpatterns = [
    path('auth/', include('Simple_Auth.urls'), name='Simple_Auth'),
]
```
Then execute the command to perform the corresponding migrations in the database. This just adds a table corresponding to the current tokens.


# How to Use
## Login
['/auth/login/']() > This POST request route requires that it be passed as an argument in JSON:
```
{
    "username":"your.username",
    "password":"your.password"
}
```
If the User and Password pair is valid, it returns the following data in JSON format:
```
{
    "username":"your.username",
    "token":"your.token"
}
```

## Use Token in Header request
You can now use the token for a validity of 7 days by default (this value can be modified in the settings added in ["settings.py"](), adding it to the request header like:
```
"Autorization":"token {your.token.here}"
```

## Valid User View
If you want to verify that the token is valid, you can make a GET request with the token in the header to the route ["./auth/check-user/"]()

If it is valid, it would respond as follows:
```
{
    "user":"your.username",
    "auth":"your.token"
}
```

## Logout
To log out and eliminate the validity of the current token, a POST request to the route ["./auth/logout/"]() is enough, where the authorization and the corresponding token are placed in the header, as mentioned above.

In case the request is successful, you will receive a 204 Successful code with no content.


# Unit Tests
All unit tests have been tested and are working correctly. You can check that you have installed the module and its configuration correctly by executing the following command:
```
python.exe .\manage.py test Simple_Auth
```