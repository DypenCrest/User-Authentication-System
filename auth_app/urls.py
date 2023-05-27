from django.urls import path
from .views import *

urlpatterns = [
    path('',dashboard_view, name='dashboard'),
    path('register/', register, name='register'),
    path('login/',custom_login, name="login"),
    path('logout/',log_out, name="logout"),
    path('about/', about, name='about'),
    path('verify-email/<str:token>/', verify_email, name='verify_email'),
    path('forgot-password/', forgot_password, name='forgot-password'),
    path('reset-password/<uidb64>/<str:token>/', reset_password, name='reset-password'),
]