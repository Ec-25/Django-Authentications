from django.urls import path
from .views import *


app_name = 'authentication'
urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('verify-email/<str:verification_token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verify-email/', ResendVerifyEmailView.as_view(), name='resend-verify-email'),
    path('signin/', SignInView.as_view(), name='signin'),
    path('signout/', LogoutView.as_view(), name='signout'),
    path('profile-view/', UserProfileView.as_view(), name='profile-view'),
    path('profile-update/', UserProfileView.as_view(), name='profile-update'),
    path('send-email-password-reset/', SendPasswordResetEmailView.as_view(), name='send-email-to-reset-password'),
    path('password-reset/<str:uidb64>/<str:token>/', UserPasswordResetView.as_view(), name='password-reset'),
    path('delete-user/', DeleteUserView.as_view(), name='delete-user'),
]