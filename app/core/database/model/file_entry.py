
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.core.database.base import Base

class FileEntry(Base):
    __tablename__ = 'file_entry'
    
    id = Column(Integer, primary_key=True)
    file_id = Column(String, unique=True, nullable=False)  # UUID
    content_hash = Column(String, unique=True, nullable=False)  # SHA256 for dedup
    mime_type = Column(String, nullable=False)
    encrypted_size_bytes = Column(Integer, nullable=False)
    original_size_bytes = Column(Integer, nullable=False)
    text_extraction_status = Column(String, default='pending')
    extracted_text_preview = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc))
    
    # Relationships
    references = relationship("FileReference", back_populates="file_entry")
    blobs = relationship("FileBlobReference", back_populates="file_entry", 
                        order_by="FileBlobReference.blob_index")
    search_index = relationship("SearchIndex", back_populates="file_entry")