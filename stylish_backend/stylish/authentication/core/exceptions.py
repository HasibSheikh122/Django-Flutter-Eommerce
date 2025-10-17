from django.utils.translation import gettext_lazy as _ 
from rest_framework.exceptions import APIException

class AccountLockedException(APIException):
    status_code = 403
    default_detail = _('Account is temporarily locked due to multiple failed attempts')
    default_code = 'account_locked'

class EmailNotVerifiedException(APIException):
    status_code = 403
    default_detail = _('Email verification required')
    default_code = 'email_not_verified'

class InvalidTokenException(APIException):
    status_code = 401
    default_detail = _('Invalid or expired token')
    default_code = 'invalid_token'

class RateLimitedException(APIException):
    status_code = 429
    default_detail = _('Reate limit exceeded. Please try again later')
    default_code = 'rate_limited'