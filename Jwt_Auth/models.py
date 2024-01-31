from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, Group as Grp, Permission


class UserManager (BaseUserManager):
    def create_user(self, email, username, first_name, last_name, password=None, verification_token=None):
        """
        Creates and saves a User with the given email, username and password.
        """
        if not email:
          raise ValueError('User must have an email address')

        user = self.model(
            email = self.normalize_email(email),
            username = username,
            first_name = first_name,
            last_name = last_name,
            verification_token = verification_token,
        )
        user.set_password(password)
        user.save(using=self._db)

        return user
    
    def create_superuser(self, email, username, first_name, last_name, password=None, password2=None, verification_token=None):
        """
        Creates and saves a superuser with the given email, username and password.
        """
        user = self.create_user(
            email,
            username,
            first_name,
            last_name,
            password,
            verification_token
        )
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user


class User (AbstractBaseUser):
    # All fields of User
    email = models.EmailField(verbose_name='Email', max_length=255, unique=True)
    username = models.CharField(verbose_name='Username', max_length=63, unique=True)
    first_name = models.CharField(verbose_name='First name', max_length=63)
    last_name = models.CharField(verbose_name='Last name', max_length=63)
    is_active = models.BooleanField(verbose_name='Is active', default=False)
    is_staff = models.BooleanField(verbose_name='Is staff', default=False)
    is_superuser = models.BooleanField(verbose_name='Is superuser', default=False)
    data_joined = models.DateTimeField(verbose_name='Date joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='Last login', auto_now=True)
    groups = models.ManyToManyField('Group', blank=True)
    user_permissions = models.ManyToManyField(Permission, blank=True)
    verification_token = models.CharField(max_length=255, blank=True, null=True)

    objects = UserManager()

    # Initial Config
    # USERNAME_FIELD are used by login, and REQUIRED_FIELDS are used by create_user
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        """
        Check if the user has a specific permission.
        
        Args:
            perm (str): The name of the permission being checked.
            obj (object, optional): The object to which the permission applies. It can be None.

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        cad = perm.split('.')
        # Check if the user is a super user, since super users have all permissions
        if self.is_superuser:
            return True

        # Check if the user has the specific permission
        elif self.user_permissions.filter(codename=cad[1]).exists():
            return True

        # Check if the user has the specific permission in any group
        elif self.groups.filter(permissions__codename=cad[1]).exists():
            return True
        
        else:
            return False

    def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

    @property
    def user_is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_staff
    
    @property
    def user_is_superuser(self):
        "Is the user a member of admins?"
        # Simplest possible answer: Yes or no
        return self.is_superuser


class Group (Grp):
    description = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = 'group'
        verbose_name_plural = 'groups'
