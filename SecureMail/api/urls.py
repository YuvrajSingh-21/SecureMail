from django.urls import path
from . import views, sync_views

urlpatterns = [
    path('emails/', views.EmailListAPI.as_view(), name='api_emails'),
    path('email/<int:id>/', views.EmailDetailAPI.as_view(), name='api_email_detail'),
    path('email/<int:id>/read/', views.MarkReadAPI.as_view(), name='api_mark_read'),
    path('profile/', views.ProfileAPI.as_view(), name='api_profile'),
    
    # Background Sync
    path('sync/start/', sync_views.SyncStartAPI.as_view(), name='api_sync_start'),
    path('sync/status/', sync_views.SyncStatusAPI.as_view(), name='api_sync_status'),
]
