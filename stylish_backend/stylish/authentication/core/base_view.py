import traceback
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError

from .response import standardized_response

logger = logging.getLogger(__name__)

class BaseAPIView(APIView):
    """Base class for all API views with common error handling and response formatting"""
    def handle_exception(self, exc):
        "Standardized exception handling for all API views"
        if isinstance(exc, AuthenticationFailed):
            return Response(standardized_response(success=False, error=str(exc)), status=status.HTTP_401_UNAUTHORIZED)
        elif isinstance(exc, TokenError):
            return Response(standardized_response(success=False, error="Invalid or expired token",), status=status.HTTP_401_UNAUTHORIZED)
        logger.error(f"Unexpected error: {str(exc)}")
        logger.error(traceback.format_exc())
        return Response(standardized_response(success=False, error= "An unexpected error occurred"), status=status.HTTP_500_INTERNAL_SERVER_ERROR)