from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

# Define the base class for SQLAlchemy models
Base = declarative_base()

# Define the Server model
class Asset(Base):
    __tablename__ = "asset"
    id = Column(Integer, primary_key=True, index=True)
    client_name = Column(String)
    vip_members=Column(String)
    ip_address = Column(String)
    customer_contact = Column(String)
    technical_contact = Column(String)

# Define the Ticket model
class Ticket(Base):
    __tablename__ = "ticket"
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("asset.id")) 
    server = relationship("Asset")
    jira_ticket_id = Column(Integer)
    output = Column(String)
    plugin_id = Column(Integer)
    plugin_name = Column(String)
    ip_address = Column(String)
    port_number = Column(Integer)
    protocol = Column(String)
    description = Column(String)
    summary = Column(String)
    solution = Column(String)
    state = Column(String)
    severity = Column(String)
    first_observed = Column(String)
    last_seen = Column(String)
