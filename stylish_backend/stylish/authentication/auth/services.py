import logging
import traceback
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from authentication.serializers import UserSerializer
from authentication.core.jwt_utils import TokenManager
from authentication.models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

class AuthenticationService:
    """Service class to handle authentication-related business logic"""
    @staticmethod
    def register(email, password, phone_number = None, first_name = None, last_name = None, request_meta = None, request = None):
        """Handle user registration with email and password"""
        if not email or not password:
            return False, {"success": False, "error":"Email and password are required."}, 400
        
        # Log registration attempt
        if request_meta:
            logger.info(f"Registration attempt from IP: {request_meta.get('REMOTE_ADDR')}")
        
        try:
            # check if email already exists
            if CustomUser.objects.filter(email=email).exists():
                return False, {"success": False, "error":"A user with this email already exists."}, 400
            # validate password strength
            try:
                validate_password(password)
            except ValidationError as e:
                return False, {"success":False, "error":", ".join(e.message)}, 400
            # create new user
            user = CustomUser.objects.create_user(email=email, password=password, is_verified=False)

            if first_name:
                user.first_name = first_name
                user.save(update_fields = ['full_name'])
            
            if last_name:
                user.first_name = last_name
                user.save(update_fields = ['last_name'])
            
            if phone_number:
                user.phone_number = phone_number
                user.save(update_fields = ['phone_number'])


            

            
            
