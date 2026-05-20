"""Django-style urls.py entry point."""

from django.urls import path
from myapp import views

urlpatterns = [
    path("admin/", views.admin_view),
]
