from django.shortcuts import render

# Create your views here.
from users.serializers import *
from rest_framework import status, permissions
from rest_framework import generics, mixins

from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from users.user_permissions import IsUserPermission
from django.http import JsonResponse

from django.contrib.auth.decorators import permission_required
from users.user_permissions import *

# user register view
class RegisterApi(generics.GenericAPIView):
    # fetching serializer data
    serializer_class = UserSerializer
    # adding authentications & auth user with role
    authentication_classes = []

    # post method for user registration
    def post(self, request, *args, **kwargs):
        '''
        This function is used for post data into database of particuar model and
            method is POST this method is used for only post the data and this function
            contating serializer data fetching serializer data and register  user with details
        '''
        parameters = request.data.copy()
        serializer = self.get_serializer(data=parameters)
        # validating serializer
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"status":"sucess","Message": "User Created Successfully.  Now Perform Login To Get Your Token"},
                            status=status.HTTP_201_CREATED)
        else:
            return Response({"Status": "Error","Message":'User Name Already Exist'}, status=status.HTTP_406_NOT_ACCEPTABLE)



class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    '''user login view'''

    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class UploadRolesApiView(generics.ListCreateAPIView):
    serializer_class = RolesSerializers
    queryset = Roles.objects.all()



class UsersDetailListApiView(generics.ListAPIView):
    # user_name = request.user.username
    serializer_class = UserSerializers
    queryset = UserProfile.objects.all()

    def get(self, request, *args, **kwargs):
        user_name = request.user.username
        serializer_class = UserSerializers
        try:
            queryset = UserProfile.objects.filter(username=user_name).values('email', 'password', 'status','OnetoOneField_Creator')
            context={'data':queryset}
            response = {
                    "status": "Success",
                    'data': context,
                }
            return Response(response, status=status.HTTP_200_OK)
        except:
            return Response({"status": "Error", "message": 'No Details Found'}, status=status.HTTP_404_NOT_FOUND)
