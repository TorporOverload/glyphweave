from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

from app.core.database.base import Base


class FileBlobReference(Base):
    __tablename__ = 'file_blob_reference'
    
    id = Column(Integer, primary_key=True)
    file_entry_id = Column(Integer, ForeignKey('file_entry.id'), nullable=False)
    blob_id = Column(String, unique=True, nullable=False)
    blob_index = Column(Integer, nullable=False)
    
    __table_args__ = (
        UniqueConstraint('file_entry_id', 'blob_index', name='uq_file_blob_index'),
    )
    
    # Relationships
    file_entry = relationship("FileEntry", back_populates="blobs")