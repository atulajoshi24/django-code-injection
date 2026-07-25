from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("calculator/", views.vulnerable_calculator, name="vulnerable_calculator"),
    path("calculator/safe/", views.safe_calculator, name="safe_calculator")
]
