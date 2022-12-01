from django.urls import path
from . import views

urlpatterns = [
    path('register', views.RegistrationView.as_view(), name='register'),
    # path('add-expense', views.add_expense, name='add-expense'),
]
