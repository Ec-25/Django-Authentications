from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.urls import reverse


class UrlReverseTest(TestCase):
    def test_login_reverse(self):
        url = reverse('Simple_Auth:login')  # Asegúrate de usar el namespace adecuado
        self.assertEqual(url, '/auth/login/')  # Ajusta el path según tu configuración de URL

    def test_logout_reverse(self):
        url = reverse('Simple_Auth:logout')  # Asegúrate de usar el namespace adecuado
        self.assertEqual(url, '/auth/logout/')  # Ajusta el path según tu configuración de URL

    def test_check_user_reverse(self):
        url = reverse('Simple_Auth:check-user')  # Asegúrate de usar el namespace adecuado
        self.assertEqual(url, '/auth/check-user/')  # Ajusta el path según tu configuración de URL


class UserViewTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.token = Token.objects.create(user=self.user)

    def test_user_view_authenticated(self):
        url = reverse('Simple_Auth:check-user')  # Ajusta el nombre de la URL según tu configuración de URL
        self.client.credentials(HTTP_AUTHORIZATION='token ' + self.token.key)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user'], 'testuser')

    def test_user_view_unauthenticated(self):
        url = reverse('Simple_Auth:check-user')  # Ajusta el nombre de la URL según tu configuración de URL
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class AuthTokenTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.user.save()

    def test_auth_token(self):
        url = reverse('Simple_Auth:login')  # Ajusta el nombre de la URL según tu configuración de URL
        data = {'username': 'testuser', 'password': 'testpassword'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)


class LogoutViewTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='token ' + self.token.key)

    def test_logout_view(self):
        url = reverse('Simple_Auth:logout')  # Ajusta el nombre de la URL según tu configuración de URL
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
