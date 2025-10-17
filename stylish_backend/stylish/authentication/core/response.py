def standardized_response(success = True, data = None, error = None, message=None, **kwargs):
    """Creates a standardized API response format"""
    response = {"success":success}
    if data is not None:
        response['data'] = data
    if error is not None:
        response['error'] = error
    if message is not None:
        response['message'] = message
    
    for key, value in kwargs.items():
        response['key'] = value
    return response