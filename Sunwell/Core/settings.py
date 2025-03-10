from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-tcrkjmoe)!gydl_6(hdih)zz7^wr=nd9usij81^%@p21#@z%@b'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'App1',

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'App1.user_activity_log.UserActivityMiddleware',
    'App1.middleware.UserActivityLoggingMiddleware',
]

ROOT_URLCONF = 'Core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR,'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'App1.context_processor.get_super_admin',
                'App1.context_processor.get_custom_user',
                'App1.context_processor.sys_auto_logout',
                
            ],
        },
    },
]

WSGI_APPLICATION = 'Core.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# MSSQL Database Connection

#Read DB Details from .env file
# DATABASES = {
#     'default': {
#         'ENGINE': 'mssql',
#         'NAME': os.getenv('DATABASE_NAME', 'default_db'),
#         'USER': os.getenv('DATABASE_USER', 'default_user'),
#         'PASSWORD': os.getenv('DATABASE_PASSWORD', 'default_password'),
#         'HOST': os.getenv('DATABASE_HOST', 'localhost'),
#         'PORT': os.getenv('DATABASE_PORT', '5432'),

        
#     }
# }

# print("Database Details:")
# print("NAME:", os.getenv('DATABASE_NAME'))
# print("USER:", os.getenv('DATABASE_USER'))
# print("PASSWORD:", os.getenv('DATABASE_PASSWORD'))
# print("HOST:", os.getenv('DATABASE_HOST'))
# print("PORT:", os.getenv('DATABASE_PORT'))

# DATABASES = {
#     'default': {
#         'ENGINE': 'mssql',  
#         'NAME': 'ESTDAS',
#         'USER': 'Sunwell',
#         'PASSWORD': 'sunwell@123',
#         'HOST': 'Darshan\\SQLEXPRESS',
#         'PORT': '',

#         'OPTIONS': {
#             'driver': 'ODBC Driver 18 for SQL Server',
#             'extra_params': 'TrustServerCertificate=yes;',  # This is sometimes needed if SSL is not setup
#         },
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/



STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # This is for development
]

# This is required in production mode (DEBUG=False)
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # Collects static files here


# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')

# settings.py
APSCHEDULER_DATETIME_FORMAT = "N j, Y, f:s a"  
APSCHEDULER_RUN_NOW_TIMEOUT = 10  


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS=True