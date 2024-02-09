from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from ..timestamp.models import Timestamp

class UserManager(BaseUserManager):
    def create_user(self, username, email, password):
        if not email:
            raise ValueError("Email is required.")
        if not password:
            raise ValueError("Password is required.")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email)
        user.set_password(password)
        user.save()
        return user

class User(AbstractBaseUser, Timestamp):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True, default='2', related_name='user_role')

    USERNAME_FIELD = 'email'

    class Meta:
        db_table = "user"
        
    def __str__(self):
        return self.email
    
    objects = UserManager()

class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(unique=True, max_length=20)

    class Meta:
        db_table = "role"

    def __str__(self):
        return self.role_name
    
class GoogleProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='google_profile')
    google_id = models.CharField(max_length=200, unique=True, null=True)
    access_token = models.CharField(max_length=200, null=True)
    refresh_token = models.CharField(max_length=200, null=True)
    # ... other fields you need for Google integration

    def __str__(self):
        return self.user.email