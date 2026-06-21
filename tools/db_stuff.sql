DROP TABLE IF EXISTS content_tok;

CREATE VIRTUAL TABLE content_tok USING fts5vocab('search_index', 'row');

SELECT term, cnt FROM content_tok ORDER BY cnt DESC LIMIT 60;


SELECT term, cnt FROM content_tok
WHERE term >= 'ހ' AND term < 'ޱ'
ORDER BY cnt DESC
LIMIT 60;

SELECT rowid, substr(c0, 1, 80) AS preview
FROM search_index_content
LIMIT 20;


SELECT term, cnt, hex(term) AS codepoints, length(term) AS len
FROM content_tok
ORDER BY cnt DESC
LIMIT 20;

SELECT term, cnt, hex(term) AS codepoints, length(term) AS len
FROM content_tok
WHERE hex(term) LIKE 'DE%' OR hex(term) LIKE 'DF%'
ORDER BY cnt DESC
LIMIT 40;
