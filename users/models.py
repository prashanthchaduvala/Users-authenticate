from django.db import models

# Create your models here.
from django.db import models

# Create your models here.
from django.db import models

from django.utils.translation import gettext_lazy as _
from django.db import models


from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.base_user import BaseUserManager

from rest_framework_simplejwt.tokens import RefreshToken







class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given mobile and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        # email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class Roles(models.Model):
    ROLE_CHOICES = (
        ('manager', 'manager'),
        ('employee', 'employee'),
    )
    role = models.CharField(max_length=8, choices=ROLE_CHOICES, default=False)


class UserProfile(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=200, unique=True, null=True, blank=True)
    email = models.EmailField(_('email address'), blank=True, null=True)
    password = models.CharField(_('password'), max_length=500, blank=True, null=True)
    status = models.BooleanField(_('active'), default=True, null=True)
    OnetoOneField_Creator = models.OneToOneField(Roles, null=True, on_delete=models.CASCADE)


    objects = UserManager()

    USERNAME_FIELD = 'username'  # User should be able to login with
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def refresh(self):
        refresh = RefreshToken.for_user(self)
        return str(refresh)

    def access(self):
        refresh = RefreshToken.for_user(self)
        return str(refresh.access_token)





