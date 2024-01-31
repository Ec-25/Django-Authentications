from django.contrib import admin
from .models import User, Group, Grp
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, GroupAdmin as BaseGroupAdmin


class UserModelAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ('id', 'email', 'username', 'first_name', 'last_name', 'is_staff', 'is_superuser', 'is_active')
    list_filter = ('username', 'last_name', 'is_staff', 'is_superuser')
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'first_name', 'last_name')}),
        ('Permissions', {'fields': ('groups', 'user_permissions')}),
        ('Authorization', {'fields': ('is_superuser', 'is_staff', 'is_active')}),
    )

    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 'password1', 'password2')
        }),
    )

    # allow search by
    search_fields = ('email', 'username', 'first_name', 'last_name')
    # Sort list by
    ordering = ('id',)
    filter_horizontal = ()


class GroupModelAdmin(BaseGroupAdmin):
    # The fields to be used in displaying the Group model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on auth.User.
    list_display = ('name', 'description')
    # list_filter = ('name',)
    fieldsets = (
        ('Group Credentials', {'fields': ('name', 'description')}),
        ('Group Permissions', {'fields': ('permissions',)}),
    )

    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('name',)
        }),
    )

    # allow search by
    search_fields = ('name',)
    # Sort list by
    ordering = ('name',)
    filter_horizontal = ()

# Now register the new UserModelAdmin...
admin.site.register(User, UserModelAdmin)

# Now register the GroupModelAdmin...
admin.site.unregister(Grp)
admin.site.register(Group, GroupModelAdmin)
