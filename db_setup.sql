CREATE TABLE results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain_name TEXT UNIQUE,
	spf_string TEXT,
	dmarc_string TEXT,
	spf_all TEXT,
	dmarc_p TEXT
);