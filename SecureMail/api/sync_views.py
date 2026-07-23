from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from ..services.sync_manager import SyncManager
from ..models import SyncJob
from django.utils.decorators import method_decorator
from ..decorators import rate_limit_view

@method_decorator(rate_limit_view(key='user', rate='3/m'), name='dispatch')
class SyncStartAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        full_sync = request.data.get('all', False)
        manager = SyncManager(request.user)
        job = manager.start_sync(full_sync=full_sync)
        
        if job:
            return Response({
                'job_id': job.id,
                'status': job.status,
                'message': 'Synchronization started successfully.'
            })
        return Response({'error': 'Failed to start synchronization. Gmail not connected.'}, status=400)

@method_decorator(rate_limit_view(key='user', rate='60/m'), name='dispatch')
class SyncStatusAPI(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        job = SyncJob.objects.filter(user=request.user).order_by('-created_at').first()
        if not job:
            return Response({'status': 'NONE', 'message': 'No synchronization jobs found.'})
            
        return Response({
            'id': job.id,
            'status': job.status,
            'total': job.total_messages,
            'synced': job.synced_messages,
            'progress': (job.synced_messages / job.total_messages * 100) if job.total_messages > 0 else 0,
            'updated_at': job.updated_at
        })
