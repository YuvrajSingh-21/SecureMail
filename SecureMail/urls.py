from django.urls import path, include
from . import views, api_views, google_auth_views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    
    # Google OAuth
    path('auth/google/login/', google_auth_views.google_login, name='google_login'),
    path('auth/google/callback/', google_auth_views.google_callback, name='google_callback'),
    path('auth/google/disconnect/', google_auth_views.google_disconnect, name='google_disconnect'),
    
    path('dashboard/', views.dashboard, name='dashboard'),
    path('inbox/', views.inbox, name='inbox'),
    path('inbox/<str:folder>/', views.inbox, name='inbox_folder'),
    path('sync/', views.sync_gmail, name='sync_gmail'),
    path('email/<int:id>/', views.email_view, name='email_view'),
    path('email/<int:id>/star/', views.toggle_star, name='toggle_star'),
    path('email/<int:id>/delete/', views.delete_email, name='delete_email'),
    path('compose/', views.compose, name='compose'),
    path('reports/', views.reports, name='reports'),
    path('settings/', views.settings_view, name='settings'),
    path('profile/', views.profile_view, name='profile'),
    
    # API Endpoints
    path('api/', include('SecureMail.api.urls')),
]
