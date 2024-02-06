from django.contrib import admin
from .models import Member
"""
registering created models in admin menu
"""
# Register your models here.
admin.site.register(Member)
