#!/usr/bin/env python3
""" this is the authentication Module """

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from typing import Union
from user import User
from uuid import uuid4


def _hash_password(password: str) -> str:
    """Generates a hashed version of the given password."""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()


def _generate_uuid() -> str:
    """Creates and returns a new unique identifier (UUID) as a string."""
    return str(uuid4())


class Auth:
    """Class for handling authentication processes with the database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user and saves them to the database.
        Returns: The created User object
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user
        else:
            raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials.
        Returns: True if the credentials are valid, otherwise False
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        if bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
            return True

        return False

    def create_session(self, email: str) -> str:
        """Creates a session ID for the user and stores it in the database.
        Returns: The session ID as a string
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Fetches a user from the database based on their session ID.
        Returns: The User object if found, otherwise None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Ends the user's session by removing their session ID.
        Returns: None
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a token for resetting the user's password.
        Returns: The generated reset token as a string
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("User not found")

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password using the provided reset token.
        Returns: None
        """
        if not reset_token or not password:
            return None

        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")

        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
