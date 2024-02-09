from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('register/', views.register_view, name='register'),
    path('google-login/', views.google_login, name='google_login'),
    path('auth-callback/', views.auth_callback, name='auth_callback'),
    path('telegram-auth/', views.telegram_auth, name='telegram_auth'),
]