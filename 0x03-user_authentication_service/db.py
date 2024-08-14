#!/usr/bin/env python3
"""
Database module for handling ORM operations.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar
from user import Base, User


class DB:
    """
    Database class for managing ORM operations.
    """

    def __init__(self):
        """
        Initialize the database engine and create all tables.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """
        Lazy-loaded session property.
        Creates a new session if it doesn't exist.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add a new user to the database.

        Args:
            email (str): The user's email address.
            hashed_password (str): The user's hashed password.

        Returns:
            User: The newly created User object.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Find a user in the database by specified keyword arguments.

        Args:
            **kwargs: Arbitrary keyword arguments corresponding to User attributes.

        Returns:
            User: The first user that matches the specified criteria.

        Raises:
            InvalidRequestError: If no keyword arguments are provided or an invalid key is used.
            NoResultFound: If no matching user is found.
        """
        if not kwargs:
            raise InvalidRequestError("No keyword arguments provided.")

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise InvalidRequestError(f"Invalid attribute: {key}")

        user = self._session.query(User).filter_by(**kwargs).first()

        if user is None:
            raise NoResultFound("No result found for the specified criteria.")

        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user's attributes in the database.

        Args:
            user_id (int): The ID of the user to be updated.
            **kwargs: Arbitrary keyword arguments corresponding to User attributes.

        Raises:
            ValueError: If an invalid attribute key is provided.

        Returns:
            None
        """
        user = self.find_user_by(id=user_id)

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise ValueError(f"Invalid attribute: {key}")

        for key, value in kwargs.items():
            setattr(user, key, value)

        self._session.commit()
