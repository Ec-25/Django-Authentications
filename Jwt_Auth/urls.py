from django.urls import path
from .views import *


urlpatterns = [
    path("register/", UserRegisterView.as_view(), name="register"),
    path("register/verify", VerifyEmail.as_view(), name="verify-email"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("logout/", UserLogoutView.as_view(), name="logout"),
    path("profile/view/", UserProfileView.as_view(), name="profile-view"),
    path("profile/update/", UserUpdateView.as_view(), name="profile-edit"),
    path("profile/delete/", UserDeleteView.as_view(), name="profile-delete"),
    path("password/change/", UserChangePasswordView.as_view(), name="user-password-change"),
    path("password/verify/<str:uidb64>/<str:token>/", UserPasswordVerifyResetView.as_view(), name="user-password-reset"),
    path("password/reset/", UserPasswordResetView.as_view(), name="user-password-reset"),
]
