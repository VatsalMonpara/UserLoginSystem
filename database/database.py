from config import DB_URL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
engine = create_engine(DB_URL)
Sessionlocal = sessionmaker(bind=engine)