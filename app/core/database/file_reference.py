
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.core.database.base import Base

class FileReference(Base):
    __tablename__ = 'file_reference'
    
    id = Column(Integer, primary_key=True)
    file_entry_id = Column(Integer, ForeignKey('file_entry.id'), nullable=False)
    folder_id = Column(Integer, ForeignKey('folders.id'), nullable=True)
    file_name = Column(String, nullable=False)
    virtual_file_path = Column(String, nullable=False, index=True)  
    added_at = Column(DateTime, default=datetime.now(timezone.utc))
    modified_at = Column(DateTime, default=datetime.now(timezone.utc), 
        onupdate=datetime.now(timezone.utc))
    accessed_at = Column(DateTime, default=datetime.now(timezone.utc))
    
    # Relationships
    file_entry = relationship("FileEntry", back_populates="references")
    folder = relationship("Folder", back_populates="files")
    wal_entries = relationship("WalEntry", back_populates="file_reference")
