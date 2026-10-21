from django.urls import path,re_path
from . import views
urlpatterns=[
 re_path(r'^collections/(?P<target>[a-z0-9][a-z0-9_-]{0,63})/archives/(?P<digest>[0-9a-f]{64})/notices/$',views.notice),
 path('.well-known/zog/archive-mirror/ready',views.ready),
 path('archives/',views.administrator_catalogue),
 re_path(r'^collections/(?P<target>[a-z0-9][a-z0-9_-]{0,63})/$',views.catalogue),
 re_path(r'^collections/(?P<target>[a-z0-9][a-z0-9_-]{0,63})/objects/(?P<digest>[0-9a-f]{64})$',views.object_download),
 re_path(r'^collections/(?P<target>[a-z0-9][a-z0-9_-]{0,63})/archives/(?P<digest>[0-9a-f]{64})\.tar\.xz$',views.download),
]
