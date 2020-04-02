-- Self-reported case

CREATE TABLE siphash (
    sip        bytea NOT NULL,
    stime      timestamp NOT NULL,
    CONSTRAINT sipid PRIMARY KEY(sip, stime)
);

CREATE INDEX sipindex ON siphash USING HASH (sip);

CREATE TABLE sreport (
    value      bytea NOT NULL,
    region     char(3) NOT NULL,
    stime      timestamp NOT NULL,
    CONSTRAINT sreportid PRIMARY KEY(value, region)
);

CREATE INDEX sindex ON sreport (stime, region);


-- Hospital-reported case

CREATE TABLE hkey (
    key        bytea PRIMARY KEY,
    parent     bytea NOT NULL,
    sig        bytea NOT NULL,
    pathlen    smallint NOT NULL
);

CREATE TABLE hcode (
    code      bytea PRIMARY KEY
);

CREATE TABLE hreport (
    value      bytea NOT NULL,
    region     char(3) NOT NULL,
    stime      timestamp NOT NULL,
    CONSTRAINT hreportid PRIMARY KEY(value, region)
);

CREATE INDEX hindex ON hreport (stime, region);


-- Development help

CREATE TABLE rssimeasure (
    id        serial PRIMARY KEY,
    value     bytea NOT NULL,
    manuf     varchar(30) NOT NULL,
    model     varchar(40) NOT NULL,
    rssi      smallint NOT NULL
);
