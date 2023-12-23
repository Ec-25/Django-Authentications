from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from . import views

app_name = 'Simple_Auth'

urlpatterns = [
    path('check-user/', views.UserView.as_view(), name="check-user"),
    path('login/', views.AuthToken.as_view(), name="login"),
    path('logout/', views.LogoutView.as_view(), name="logout"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
