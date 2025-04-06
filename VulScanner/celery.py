import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VulScanner.settings')
app = Celery('VulScanner')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
app.conf.broker_url = 'redis://localhost:6379/0'
app.conf.result_backend = 'redis://localhost:6379/0'





# Use pickle serializer for complex objects
app.conf.task_serializer = 'pickle'
app.conf.result_serializer = 'pickle'
app.conf.accept_content = ['json', 'pickle']