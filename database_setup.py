from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    # Stores the User data
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Park(Base):
    # Stores Park data added by User
    __tablename__ = 'park'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    flora_list = relationship('FloraList', cascade='all, delete-orphan')


    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }


class FloraList(Base):
    # Stores Flora Data added by User
    __tablename__ = 'flora_list'

    name = Column(String(80), nullable=False)

    id = Column(Integer, primary_key=True)
    description = Column(String(50))
    number = Column(String(20))
    type = Column(String(20))
    park_id = Column(Integer, ForeignKey('park.id'))
    park = relationship(Park)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,

            'description': self.description,
            'id': self.id,
            'number': self.number,
            'type': self.type,
        }


engine = create_engine('postgresql://catalog:database@localhost/parkfloradatabase')


Base.metadata.create_all(engine)
