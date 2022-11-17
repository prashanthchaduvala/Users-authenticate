from rest_framework.permissions import  BasePermission

from rest_framework.permissions import BasePermission

class IsUserPermission(BasePermission):
    """
    Check if user is a mkjnk.
    """

    message = "The user is not  active."

    def has_permission(self, request, view):
        return request.user.is_active