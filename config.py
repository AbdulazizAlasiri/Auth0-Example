
#  IMPORTANT: Make sure the change the secret key and the database password on prodaction.
#  IMPORTANT: Add this file to gitignore.

import os
# SECRET_KEY = os.urandom(32)
SECRET_KEY = b'RzsLNcaHPDb3aHSeFthA43GPBlkvw9o_YunU4NIEdm0='
# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode.
DEBUG = True

SQLALCHEMY_TRACK_MODIFICATIONS = False
# Connect to the database


# 'postgresql://myusername:mypassword@localhost:5432/mydatabase'
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:12@localhost:5432/eshop'
