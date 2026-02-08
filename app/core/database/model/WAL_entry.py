
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.core.database.base import Base

class WalEntry(Base):
    __tablename__ = 'wal_entries'
    
    id = Column(Integer, primary_key=True)
    file_reference_id = Column(Integer, ForeignKey('file_reference.id'), nullable=False)
    operation = Column(String, nullable=False)
    offset = Column(Integer, default=0)
    length = Column(Integer, nullable=False)
    temp_blob_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    flushed = Column(Boolean, default=False)
    flushed_at = Column(DateTime, nullable=True)
    
    # Relationships
    file_reference = relationship("FileReference", back_populates="wal_entries",
                                  foreign_keys=[file_reference_id])