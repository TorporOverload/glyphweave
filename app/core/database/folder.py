
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.core.database.base import Base


class Folder(Base):
    __tablename__ = 'folders'
    
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('folders.id'), nullable=True)
    folder_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc))
    
    # Relationships
    parent = relationship("Folder", remote_side=[id], backref="subfolders")
    files = relationship("FileReference", back_populates="folder")
