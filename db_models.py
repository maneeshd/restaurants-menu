"""
Models for the database tables
"""
from os import getenv
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine


BASE = declarative_base()


class User(BASE):
    """
    Model for User table
    """
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)
    email = Column(String(64), nullable=False)
    picture = Column(String(256))

    restaurant = relationship("Restaurant", cascade="all,delete",
                              backref="User")
    menu_item = relationship("MenuItem", cascade="all,delete", backref="User")

    @property
    def serialize(self):
        """
        Serialize the object to JSON

        :return: JSON
        """
        return dict(
            id=self.id,
            name=self.name,
            email=self.email,
            picture=self.picture
        )

    def __str__(self):
        """
        String representation of object

        :return: str
        """
        return "<id: {0}, name: {1}, email: {2}>".format(self.id, self.name,
                                                         self.email)


class Restaurant(BASE):
    """
    Model for Restaurant table
    """
    __tablename__ = "restaurant"
    rid = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE",
                                         onupdate="CASCADE"))

    user = relationship("User",
                        backref=backref("Restaurant", passive_deletes=True,
                                        cascade="all,delete"))
    menu_item = relationship("MenuItem", cascade="all,delete",
                             backref="Restaurant")

    @property
    def serialize(self):
        """
        Serialize the object to JSON

        :return: JSON
        """
        return dict(
            rid=self.rid,
            name=self.name,
            user_id=self.user_id
        )

    def __str__(self):
        """
        String representation of object

        :return: str
        """
        return "<rid: {0}, name: {1}>".format(self.rid, self.name)


class MenuItem(BASE):
    """
    Model for MenuItem table.
    """
    __tablename__ = "menu_item"
    mid = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    course = Column(String(32))
    description = Column(String(256))
    price = Column(String(8))
    rid = Column(Integer, ForeignKey("restaurant.rid", ondelete="CASCADE",
                                     onupdate="CASCADE"))
    user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE",
                                         onupdate="CASCADE"))

    user = relationship("User",
                        backref=backref("MenuItem", passive_deletes=True,
                                        cascade="all,delete"))
    restaurant = relationship("Restaurant",
                              backref=backref("MenuItem", passive_deletes=True,
                                              cascade="all,delete"))

    @property
    def serialize(self):
        """
        Serialize the object to JSON

        :return: JSON
        """
        return dict(
            mid=self.mid,
            name=self.name,
            course=self.course,
            description=self.description,
            price=self.price,
            rid=self.rid,
            user_id=self.user_id
        )

    def __str__(self):
        """
        String representation of object

        :return: str
        """
        return "<mid: {0}, name: {1}>".format(self.mid, self.name)


def create_models(db_uri):
    """
    Create the database tables
    :param db_uri: Databse URI
    :return: None
    """
    print("Using db_uri: {0} to create models...".format(db_uri))
    db_engine = create_engine(db_uri)
    BASE.metadata.create_all(db_engine)
    print("Database models have been created successfully.")


if __name__ == "__main__":
    if getenv("DATABASE_URL"):
        create_models(getenv("DATABASE_URL"))
    else:
        create_models("sqlite:///restaurant_menu_with_users.db")
