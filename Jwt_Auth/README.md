# Django REST Framework Complete Authentication API with Simple JWT
Django authenticator with JWT and Rest framework as an API, ready to implement.

In authentication\urls.py there are commented lines since these reflect different ways to reset a user's password, depending on the level of security required.

# To Run this Project follow below:
```
mkvirtualenv authenv
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
```