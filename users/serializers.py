from django.contrib import auth

from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from users.models import *
from django.contrib.auth import authenticate
from django.utils.text import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class UserSerializer(serializers.ModelSerializer):
    """
    user register serializer and required fields
    """

    # mobile = serializers.RegexField("[0-9]{10}",min_length=10,max_length=10)
    username = serializers.CharField()
    password = serializers.CharField(write_only=True, max_length=500)
    email = serializers.EmailField(max_length=155, min_length=3, required=True)


    def validate_mobile(self, user_name):
        is_already_exists = UserProfile.objects.filter(username=user_name).exists()
        if is_already_exists:
            raise serializers.ValidationError('username already exists')
        return user_name

    def validate_email(self, user_email):
        is_already_exists = UserProfile.objects.filter(email=user_email).exists()
        if is_already_exists:
            raise serializers.ValidationError('email already exists')
        return user_email


    class Meta:
        # get the model name
        model = UserProfile
        # required fields
        fields = ("id", "username", "email", "password","OnetoOneField_Creator")
        # fields="__all__"

    def create(self, validated_data):
        user = super(UserSerializer, self).create(validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user









class LoginSerializer(serializers.ModelSerializer):
    '''
    Login user serializer with required fields
    '''

    username = serializers.CharField()
    password = serializers.CharField(max_length=150, min_length=6, write_only=True)
    refresh = serializers.CharField(max_length=135, min_length=6, read_only=True)
    access = serializers.CharField(max_length=135, min_length=6, read_only=True)

    class Meta:
        # model name
        model = UserProfile
        # required fields
        fields = ['username', 'password',  'access', 'refresh', ]

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        user = auth.authenticate(username=username, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled , contact admin')
        return {
            'username': user.username,
            'refresh': user.refresh,
            'access': user.access,
        }


class RolesSerializers(serializers.ModelSerializer):
    """
    Movie Serializer
    """

    class Meta:
        model = Roles
        fields = '__all__'


class UserSerializers(serializers.ModelSerializer):
    """
    Movie Serializer
    """

    class Meta:
        model = UserProfile
        fields = ['email','password','status','OnetoOneField_Creator']


