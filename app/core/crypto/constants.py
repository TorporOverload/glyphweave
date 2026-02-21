"""Constants used in crypto module"""

# File encryption thresholds
CHUNK_SIZE: int = 64 * 1024  # 64KB chunks 
LARGE_FILE_THRESHOLD: int = 5 * 1024 * 1024  # 5MB
BLOB_SIZE_MAX = 10 * 1024 * 1024
FILE_HEADER_SIZE_BYTES = 37

# Chunked format identifiers
HEADER_AAD: bytes = b"GWHv1"
CHUNKED_MAGIC: bytes = b"GWCH"
CHUNKED_VERSION: int = 1

# Key sizes
MASTER_KEY_SIZE: int = 32  # 256 bits
NONCE_SIZE: int = 12  # 96 bits for GCM
GCM_TAG_SIZE: int = 16  # 128 bits

# Argon2id parameters
ARGON2_MEMORY_KB: int = 64 * 1024  # 64 MB
ARGON2_ITERATIONS: int = 10
ARGON2_PARALLELISM: int = 4
ARGON2_SALT_SIZE: int = 16
ARGON2_LENGTH: int = 32

# HKDF info strings for domain separation
HKDF_INFO_FILE: bytes = b"glyphweave_file_v1:"
HKDF_INFO_DATABASE: bytes = b"glyphweave_database_v1"
HKDF_INFO_EVENT: bytes = b"glyphweave_event_v1"
HKDF_INFO_RECOVERY: bytes = b"glyphweave_recovery_v1"
HKDF_INFO_BACKUP: bytes = b"glyphweave_backup_v1"

# Associated data for key wrapping
KEY_WRAP_AAD: bytes = b"glyphweave_v1"


# Check value for password verification
CHECK_PLAINTEXT: bytes = b"GLYPHWEAVE_CHECK_V1"
# FUSE-specific constants
FUSE_CHUNK_SIZE: int = 64 * 1024 
FUSE_METADATA_AAD: bytes = b"GWMETAv1"
FUSE_CHUNK_AAD_PREFIX: bytes = b"GWCHKv1"