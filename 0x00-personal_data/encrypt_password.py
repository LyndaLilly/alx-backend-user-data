#!/usr/bin/env python3
"""
this is password encrypting
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ this returns a hashed password string byte """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ this gets required password that matches the hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
