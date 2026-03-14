from kreuzberg import extract_file_sync, ExtractionConfig

config: ExtractionConfig = ExtractionConfig()
result = extract_file_sync("C:\\Users\\shameel\\Documents\\Docs\\އަމީންދިދި.docx"
    , config=config)

content: str = result.content
table_count: int = len(result.tables)
metadata: dict = result.metadata

print(f"Content length: {len(content)} characters")
print(f"Tables: {table_count}")
print(f"Metadata keys: {list(metadata.keys())}")
print(f"content \n {content}")

print("=====================================")


pdf_meta: dict = result.metadata.get("pdf", {})
if pdf_meta:
    print(f"Pages: {pdf_meta.get('page_count')}")
    print(f"Author: {pdf_meta.get('author')}")
    print(f"Title: {pdf_meta.get('title')}")
