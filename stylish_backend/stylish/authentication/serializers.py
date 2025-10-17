from rest_framework import serializers
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'profile_picture','profile_picture_url','phone_number', 'is_verified', 'created_at']
        read_only_fields = ['id','email','created_at','is_verified','profile_picture_url']

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            else:
                return obj.profile_picture.url
        return None


