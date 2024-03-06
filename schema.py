from pydantic import BaseModel

# Define a Pydantic BaseModel for the Server model
class Asset(BaseModel):
    # Define fields for the Server model
    client_name: str
    vip_members: str
    ip_address: str
    customer_contact: str
    technical_contact: str

# Pydantic configuration to enable ORM mode
    class Config:
        orm_mode = True

# Define a Pydantic BaseModel for the Ticket model
class Ticket(BaseModel):
    # Define fields for the Ticket model
    name: str
    asset_id: int
    jira_ticket_id: int
    output: str
    plugin_id: int
    plugin_name: str
    ip_address: str
    port_number: int
    protocol : str
    description: str
    summary: str
    solution: str
    state: str
    severity: str
    first_observed: str
    last_seen: str

    # Pydantic configuration to enable ORM mode
    class Config:
        orm_mode = True
